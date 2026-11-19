require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET;
const durations = ['小时卡', '天卡', '周卡', '月卡', '季卡', '半年卡', '年卡', '永久卡'];

if (!jwtSecret || jwtSecret.length < 32) throw new Error('JWT_SECRET 必须配置且至少 32 位');
if (!process.env.DATABASE_URL) throw new Error('必须配置 DATABASE_URL');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000
});

app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '..')));

function publicUser(row) {
  return {
    id: Number(row.id),
    name: row.name,
    email: row.email,
    role: row.role,
    department: row.department,
    status: row.status,
    balance: Number(row.balance || 0),
    lastLogin: row.last_login ? new Date(row.last_login).toLocaleString('zh-CN', { hour12: false }) : '尚未登录'
  };
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0];
}

async function getUserByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rows[0];
}

function auth(requiredRole) {
  return async (req, res, next) => {
    try {
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const claims = jwt.verify(token, jwtSecret);
      const user = await getUserById(claims.id);
      if (!user || user.status !== 'active') return res.status(401).json({ message: '账号不可用，请重新登录' });
      if (requiredRole && user.role !== requiredRole) return res.status(403).json({ message: '没有权限执行此操作' });
      req.user = { id: user.id, role: user.role, name: user.name, email: user.email };
      next();
    } catch (_) { res.status(401).json({ message: '登录已失效，请重新登录' }); }
  };
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (_) { res.status(503).json({ ok: false, message: 'PostgreSQL 数据库连接失败' }); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ message: '请输入账号和密码' });
    const user = await getUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ message: '账号或密码错误' });
    if (user.status !== 'active') return res.status(403).json({ message: '该账号已被停用' });
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name, email: user.email }, jwtSecret, { expiresIn: '8h' });
    res.json({ token, user: publicUser(user) });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', auth(), async (req, res, next) => {
  try {
    const user = await getUserById(req.user.id);
    res.json({ user: { ...req.user, balance: Number(user.balance || 0) } });
  } catch (error) { next(error); }
});

app.get('/api/users', auth('管理员'), async (_req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.set('Cache-Control', 'no-store');
    res.json({ users: rows.map(publicUser) });
  } catch (error) { next(error); }
});

app.post('/api/users/:id/recharge', auth('管理员'), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const amount = Number(req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({ message: '充值金额必须大于 0 且不超过 1000000' });
    await client.query('BEGIN');
    const { rows } = await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING balance', [amount, req.params.id]);
    if (!rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ message: '用户不存在' }); }
    await client.query('INSERT INTO recharge_logs (user_id, amount, admin_id) VALUES ($1, $2, $3)', [req.params.id, amount, req.user.id]);
    await client.query('COMMIT');
    res.json({ balance: Number(rows[0].balance) });
  } catch (error) { await client.query('ROLLBACK'); next(error); } finally { client.release(); }
});

app.post('/api/users/:id/reclaim-balance', auth('管理员'), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const amount = Number(req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({ message: '回收金额必须大于 0 且不超过 1000000' });
    await client.query('BEGIN');
    const { rows: users } = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [req.params.id]);
    const user = users[0];
    if (!user) { await client.query('ROLLBACK'); return res.status(404).json({ message: '用户不存在' }); }
    if (Number(user.balance) < amount) { await client.query('ROLLBACK'); return res.status(400).json({ message: '用户余额不足，无法回收该金额' }); }
    const { rows } = await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance', [amount, req.params.id]);
    await client.query('INSERT INTO balance_reclaim_logs (user_id, amount, admin_id) VALUES ($1, $2, $3)', [req.params.id, amount, req.user.id]);
    await client.query('COMMIT');
    res.json({ balance: Number(rows[0].balance) });
  } catch (error) { await client.query('ROLLBACK'); next(error); } finally { client.release(); }
});

app.get('/api/apps', auth(), async (_req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT id, name, description, prices FROM applications WHERE status = 'active' ORDER BY name");
    res.json({ applications: rows });
  } catch (error) { next(error); }
});

app.get('/api/admin/apps', auth('管理员'), async (_req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id, name, description, prices, status FROM applications ORDER BY name');
    res.json({ applications: rows });
  } catch (error) { next(error); }
});

app.get('/api/settings/recharge-contact', auth(), async (_req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT setting_value FROM platform_settings WHERE setting_key = 'recharge_contact'");
    res.json({ contact: rows[0]?.setting_value || '' });
  } catch (error) { next(error); }
});

app.put('/api/settings/recharge-contact', auth('管理员'), async (req, res, next) => {
  try {
    const contact = String(req.body.contact || '').trim();
    if (contact.length > 1000) return res.status(400).json({ message: '联系方式不能超过 1000 个字符' });
    await pool.query("INSERT INTO platform_settings (setting_key, setting_value) VALUES ('recharge_contact', $1) ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()", [contact]);
    res.json({ contact });
  } catch (error) { next(error); }
});

app.post('/api/apps', auth('管理员'), async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const description = String(req.body.description || '').trim();
    const prices = req.body.prices && typeof req.body.prices === 'object' && !Array.isArray(req.body.prices) ? req.body.prices : {};
    if (!name) return res.status(400).json({ message: '应用名称不能为空' });
    if (Object.values(prices).some(price => !Number.isFinite(Number(price)) || Number(price) < 0)) return res.status(400).json({ message: '售价必须是大于或等于 0 的数字' });
    const { rows } = await pool.query("INSERT INTO applications (name, description, prices, status) VALUES ($1, $2, $3::jsonb, 'active') RETURNING id, name, description, prices, status", [name, description, JSON.stringify(prices)]);
    res.status(201).json({ application: rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ message: '应用名称已存在' });
    next(error);
  }
});

app.put('/api/apps/:id', auth('管理员'), async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const description = String(req.body.description || '').trim();
    const prices = req.body.prices && typeof req.body.prices === 'object' && !Array.isArray(req.body.prices) ? req.body.prices : {};
    if (!name) return res.status(400).json({ message: '应用名称不能为空' });
    if (Object.entries(prices).some(([duration, price]) => !durations.includes(duration) || !Number.isFinite(Number(price)) || Number(price) < 0)) return res.status(400).json({ message: '卡种或售价无效' });
    const { rows } = await pool.query('UPDATE applications SET name = $1, description = $2, prices = $3::jsonb WHERE id = $4 RETURNING id, name, description, prices, status', [name, description, JSON.stringify(prices), req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: '应用不存在' });
    res.json({ application: rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ message: '应用名称已被其他应用使用' });
    next(error);
  }
});

app.delete('/api/admin/apps/:id', auth('管理员'), async (req, res, next) => {
  try {
    const { rows } = await pool.query("UPDATE applications SET status = 'inactive' WHERE id = $1 AND status = 'active' RETURNING id", [req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: '应用不存在或已下架' });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.post('/api/admin/apps/:id/restore', auth('管理员'), async (req, res, next) => {
  try {
    const { rows } = await pool.query("UPDATE applications SET status = 'active' WHERE id = $1 AND status = 'inactive' RETURNING id", [req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: '应用不存在或已恢复' });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.post('/api/apps/:id/cards/import', auth('管理员'), async (req, res, next) => {
  try {
    const duration = String(req.body.duration || '');
    const secrets = [...new Set((Array.isArray(req.body.secrets) ? req.body.secrets : []).map(value => String(value).trim()).filter(Boolean))];
    if (!durations.includes(duration) || !secrets.length || secrets.length > 500) return res.status(400).json({ message: '请选择有效时长，并导入 1 到 500 条卡密' });
    if (secrets.some(secret => secret.length > 300)) return res.status(400).json({ message: '单条卡密不能超过 300 个字符' });
    const values = [];
    const placeholders = secrets.map((secret, index) => {
      const offset = index * 3;
      values.push(req.params.id, duration, secret);
      return `($${offset + 1}, $${offset + 2}, $${offset + 3})`;
    });
    const { rowCount } = await pool.query(`INSERT INTO card_keys (application_id, duration, secret) VALUES ${placeholders.join(', ')}`, values);
    res.status(201).json({ imported: rowCount });
  } catch (error) {
    if (error.code === '23503') return res.status(404).json({ message: '应用不存在' });
    if (error.code === '23505') return res.status(409).json({ message: '导入失败：卡密已存在，请删除重复项后重试' });
    next(error);
  }
});

app.get('/api/admin/cards', auth('管理员'), async (req, res, next) => {
  try {
    const status = String(req.query.status || 'all');
    const duration = String(req.query.duration || 'all');
    if (status !== 'all' && !['available', 'sold'].includes(status)) return res.status(400).json({ message: '库存状态无效' });
    if (duration !== 'all' && !durations.includes(duration)) return res.status(400).json({ message: '卡密时长无效' });
    const filters = [];
    const values = [];
    const addFilter = value => { values.push(value); return `$${values.length}`; };
    if (req.query.applicationId && req.query.applicationId !== 'all') filters.push(`c.application_id = ${addFilter(req.query.applicationId)}`);
    if (status !== 'all') filters.push(`c.status = ${addFilter(status)}`);
    if (duration !== 'all') filters.push(`c.duration = ${addFilter(duration)}`);
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const { rows } = await pool.query(`SELECT c.id, c.application_id AS "applicationId", COALESCE(a.name, '已删除应用') AS application, c.duration, c.secret, c.status, c.sold_at AS "soldAt", c.created_at AS "createdAt" FROM card_keys c LEFT JOIN applications a ON a.id = c.application_id ${where} ORDER BY c.created_at DESC`, values);
    res.set('Cache-Control', 'no-store');
    res.json({ cards: rows });
  } catch (error) { next(error); }
});

app.delete('/api/admin/cards/:id', auth('管理员'), async (req, res, next) => {
  try {
    const { rowCount } = await pool.query("DELETE FROM card_keys WHERE id = $1 AND status = 'available'", [req.params.id]);
    if (!rowCount) return res.status(404).json({ message: '未找到可删除的库存卡密；已售卡密不能删除' });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.post('/api/admin/cards/delete-batch', auth('管理员'), async (req, res, next) => {
  try {
    const ids = [...new Set((Array.isArray(req.body.ids) ? req.body.ids : []).map(id => String(id).trim()).filter(Boolean))];
    if (!ids.length || ids.length > 1000) return res.status(400).json({ message: '请选择 1 到 1000 条卡密' });
    const { rowCount } = await pool.query("DELETE FROM card_keys WHERE id = ANY($1::bigint[]) AND status = 'available'", [ids]);
    res.json({ deleted: rowCount, skipped: ids.length - rowCount });
  } catch (error) { next(error); }
});

app.post('/api/cards/redeem', auth(), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const applicationId = String(req.body.applicationId || '');
    const duration = String(req.body.duration || '');
    await client.query('BEGIN');
    const { rows: apps } = await client.query("SELECT id, name, prices FROM applications WHERE id = $1 AND status = 'active'", [applicationId]);
    const application = apps[0];
    if (!application) { await client.query('ROLLBACK'); return res.status(404).json({ message: '请选择有效应用' }); }
    const price = Number(application.prices?.[duration]);
    if (!Number.isFinite(price) || price < 0) { await client.query('ROLLBACK'); return res.status(400).json({ message: '该时长暂未开放' }); }
    const { rows: users } = await client.query('SELECT id, balance FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = users[0];
    if (!user || Number(user.balance) < price) { await client.query('ROLLBACK'); return res.status(400).json({ message: '钱包余额不足，请联系管理员充值' }); }
    const { rows: cards } = await client.query("SELECT id, secret FROM card_keys WHERE application_id = $1 AND duration = $2 AND status = 'available' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1", [applicationId, duration]);
    const card = cards[0];
    if (!card) { await client.query('ROLLBACK'); return res.status(409).json({ message: '该应用和时长的卡密暂时缺货' }); }
    await client.query("UPDATE card_keys SET status = 'sold', sold_to = $1, sold_at = NOW() WHERE id = $2", [user.id, card.id]);
    const { rows: charged } = await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2 RETURNING balance', [price, user.id]);
    await client.query('COMMIT');
    res.json({ application: application.name, duration, price, balance: Number(charged[0].balance), cardKey: card.secret });
  } catch (error) { await client.query('ROLLBACK'); next(error); } finally { client.release(); }
});

app.get('/api/cards/history', auth(), async (req, res, next) => {
  try {
    const values = [req.user.id];
    let filter = '';
    if (req.query.applicationId && req.query.applicationId !== 'all') { values.push(req.query.applicationId); filter = ' AND c.application_id = $2'; }
    const { rows } = await pool.query(`SELECT c.id, c.application_id AS "applicationId", COALESCE(a.name, '已删除应用') AS application, c.duration, c.secret AS "cardKey", c.sold_at AS "soldAt" FROM card_keys c LEFT JOIN applications a ON a.id = c.application_id WHERE c.status = 'sold' AND c.sold_to = $1${filter} ORDER BY c.sold_at DESC LIMIT 200`, values);
    res.set('Cache-Control', 'no-store');
    res.json({ records: rows });
  } catch (error) { next(error); }
});

app.post('/api/users', auth('管理员'), async (req, res, next) => {
  try {
    const { name, email, password, role = '成员', department = '', status = 'active' } = req.body;
    if (!name || !email || !password || password.length < 6) return res.status(400).json({ message: '姓名、账号和至少6位密码不能为空' });
    const { rows } = await pool.query('INSERT INTO users (name, email, password_hash, role, department, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [name.trim(), email.trim().toLowerCase(), await bcrypt.hash(password, 12), role, department.trim(), status]);
    res.status(201).json({ user: publicUser(rows[0]) });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ message: '该账号已注册' });
    next(error);
  }
});

app.put('/api/users/:id', auth('管理员'), async (req, res, next) => {
  try {
    const { name, email, password, role, department, status, balance } = req.body;
    if (!name || !email || !role || department === undefined || !['active', 'inactive'].includes(status)) return res.status(400).json({ message: '用户资料不完整' });
    if (password && password.length < 6) return res.status(400).json({ message: '密码至少需要 6 位' });
    if (balance !== undefined && (!Number.isFinite(Number(balance)) || Number(balance) < 0 || Number(balance) > 1000000)) return res.status(400).json({ message: '余额必须是 0 到 1000000 之间的数字' });
    const values = [name.trim(), email.trim().toLowerCase(), role, department.trim(), status];
    let optionalFieldsSql = '';
    if (password) { values.push(await bcrypt.hash(password, 12)); optionalFieldsSql += `, password_hash = $${values.length}`; }
    if (balance !== undefined) { values.push(Number(balance)); optionalFieldsSql += `, balance = $${values.length}`; }
    values.push(req.params.id);
    const { rows } = await pool.query(`UPDATE users SET name = $1, email = $2, role = $3, department = $4, status = $5${optionalFieldsSql} WHERE id = $${values.length} RETURNING *`, values);
    if (!rows[0]) return res.status(404).json({ message: '用户不存在' });
    res.json({ user: publicUser(rows[0]) });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ message: '该账号已注册' });
    next(error);
  }
});

app.delete('/api/users/:id', auth('管理员'), async (req, res, next) => {
  try {
    if (String(req.user.id) === String(req.params.id)) return res.status(400).json({ message: '不能删除当前登录管理员' });
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.status(204).end();
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error.code === '42P01') return res.status(503).json({ message: '数据库表尚未创建，请执行 schema.sql 后重试' });
  res.status(500).json({ message: '服务器内部错误' });
});

async function bootstrap() {
  await pool.query('SELECT 1');
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (!adminEmail) throw new Error('首次启动必须在 .env 配置 ADMIN_EMAIL');
  const existing = await getUserByEmail(adminEmail);
  if (!existing) {
    const password = process.env.ADMIN_PASSWORD;
    if (!password || password.length < 6) throw new Error('首次启动必须在 .env 配置 ADMIN_PASSWORD，且至少 6 位');
    await pool.query("INSERT INTO users (name, email, password_hash, role, department, status) VALUES ($1, $2, $3, '管理员', '管理部', 'active')", [process.env.ADMIN_NAME || '管理员', adminEmail, await bcrypt.hash(password, 12)]);
    console.log(`已创建首个管理员：${adminEmail}`);
  }
  app.listen(port, () => console.log(`森序管理平台运行于 http://localhost:${port}`));
}

bootstrap().catch(error => { console.error('启动失败：', error.message || error); process.exit(1); });
