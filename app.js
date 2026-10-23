require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudbase = require('@cloudbase/js-sdk');

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret || jwtSecret.length < 32) throw new Error('JWT_SECRET 必须配置且至少 32 位');
if (!process.env.CLOUDBASE_ENV_ID || !process.env.CLOUDBASE_APIKEY) throw new Error('必须配置 CLOUDBASE_ENV_ID 和 CLOUDBASE_APIKEY');

const cloudApp = cloudbase.init({ env: process.env.CLOUDBASE_ENV_ID, accessKey: process.env.CLOUDBASE_APIKEY });
const db = cloudApp.rdb();
const usersTable = () => db.from('users');

app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '..')));

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    department: row.department,
    status: row.status,
    balance: Number(row.balance || 0),
    lastLogin: row.last_login ? new Date(row.last_login).toLocaleString('zh-CN', { hour12: false }) : '尚未登录'
  };
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

async function getUserById(id) {
  const { data, error } = await usersTable().select('*').eq('id', id).limit(1);
  if (error) throw error;
  return data[0];
}

async function getUserByEmail(email) {
  const { data, error } = await usersTable().select('*').eq('email', email).limit(1);
  if (error) throw error;
  return data[0];
}

app.get('/api/health', async (_req, res) => {
  try { const { error } = await usersTable().select('id', { head: true, count: 'exact' }); if (error) throw error; res.json({ ok: true }); }
  catch (_) { res.status(503).json({ ok: false, message: 'CloudBase 数据库连接失败' }); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ message: '请输入邮箱和密码' });
    const user = await getUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ message: '账号或密码错误' });
    if (user.status !== 'active') return res.status(403).json({ message: '该账号已被停用' });
    const { error } = await usersTable().update({ last_login: new Date().toISOString() }).eq('id', user.id);
    if (error) throw error;
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name, email: user.email }, jwtSecret, { expiresIn: '8h' });
    res.json({ token, user: publicUser(user) });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', auth(), async (req, res, next) => {
  try { const user = await getUserById(req.user.id); res.json({ user: { ...req.user, balance: Number(user.balance || 0) } }); }
  catch (error) { next(error); }
});

app.get('/api/users', auth('管理员'), async (_req, res, next) => {
  try { res.set('Cache-Control', 'no-store'); const { data, error } = await usersTable().select('*').order('created_at', { ascending: false }); if (error) throw error; res.json({ users: data.map(publicUser) }); }
  catch (error) { next(error); }
});

app.post('/api/users/:id/recharge', auth('管理员'), async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({ message: '充值金额必须大于 0 且不超过 1000000' });
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ message: '用户不存在' });
    const nextBalance = Number(user.balance || 0) + amount;
    let result = await usersTable().update({ balance: nextBalance }).eq('id', req.params.id);
    if (result.error) throw result.error;
    result = await db.from('recharge_logs').insert({ user_id: req.params.id, amount, admin_id: req.user.id });
    if (result.error) throw result.error;
    res.json({ balance: nextBalance });
  } catch (error) { next(error); }
});

app.get('/api/apps', auth(), async (_req, res, next) => {
  try {
    const { data, error } = await db.from('applications').select('id, name, description, prices').eq('status', 'active').order('name');
    if (error) throw error;
    res.json({ applications: data });
  } catch (error) { next(error); }
});

app.get('/api/settings/recharge-contact', auth(), async (_req, res, next) => {
  try {
    const { data, error } = await db.from('platform_settings').select('setting_value').eq('setting_key', 'recharge_contact').limit(1);
    if (error) throw error;
    res.json({ contact: data[0]?.setting_value || '' });
  } catch (error) { next(error); }
});

app.put('/api/settings/recharge-contact', auth('管理员'), async (req, res, next) => {
  try {
    const contact = String(req.body.contact || '').trim();
    if (contact.length > 1000) return res.status(400).json({ message: '联系方式不能超过 1000 个字符' });
    const { data, error } = await db.from('platform_settings').select('setting_key').eq('setting_key', 'recharge_contact').limit(1);
    if (error) throw error;
    const result = data.length
      ? await db.from('platform_settings').update({ setting_value: contact, updated_at: new Date().toISOString() }).eq('setting_key', 'recharge_contact')
      : await db.from('platform_settings').insert({ setting_key: 'recharge_contact', setting_value: contact });
    if (result.error) throw result.error;
    res.json({ contact });
  } catch (error) { next(error); }
});

app.post('/api/apps', auth('管理员'), async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const description = String(req.body.description || '').trim();
    const prices = req.body.prices && typeof req.body.prices === 'object' ? req.body.prices : {};
    if (!name) return res.status(400).json({ message: '应用名称不能为空' });
    if (Object.values(prices).some(price => !Number.isFinite(Number(price)) || Number(price) < 0)) return res.status(400).json({ message: '售价必须是大于或等于 0 的数字' });
    const { data: existing, error: lookupError } = await db.from('applications').select('id').eq('name', name).limit(1);
    if (lookupError) throw lookupError;
    if (existing.length) return res.status(409).json({ message: '应用名称已存在' });
    const { data, error } = await db.from('applications').insert({ name, description, prices, status: 'active' }).select();
    if (error) throw error;
    res.status(201).json({ application: data[0] });
  } catch (error) { next(error); }
});

app.put('/api/apps/:id', auth('管理员'), async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const description = String(req.body.description || '').trim();
    const prices = req.body.prices && typeof req.body.prices === 'object' && !Array.isArray(req.body.prices) ? req.body.prices : {};
    const allowedDurations = ['小时卡', '天卡', '周卡', '月卡', '季卡', '半年卡', '年卡', '永久卡'];
    if (!name) return res.status(400).json({ message: '应用名称不能为空' });
    if (Object.entries(prices).some(([duration, price]) => !allowedDurations.includes(duration) || !Number.isFinite(Number(price)) || Number(price) < 0)) return res.status(400).json({ message: '卡种或售价无效' });
    const { data: existing, error: lookupError } = await db.from('applications').select('id').eq('name', name).limit(1);
    if (lookupError) throw lookupError;
    if (existing.some(item => String(item.id) !== String(req.params.id))) return res.status(409).json({ message: '应用名称已被其他应用使用' });
    const { data, error } = await db.from('applications').update({ name, description, prices }).eq('id', req.params.id).select();
    if (error) throw error;
    if (!data?.length) return res.status(404).json({ message: '应用不存在' });
    res.json({ application: data[0] });
  } catch (error) { next(error); }
});

app.post('/api/apps/:id/cards/import', auth('管理员'), async (req, res, next) => {
  try {
    const duration = String(req.body.duration || '');
    const secrets = [...new Set((Array.isArray(req.body.secrets) ? req.body.secrets : []).map(value => String(value).trim()).filter(Boolean))];
    const durations = ['小时卡', '天卡', '周卡', '月卡', '季卡', '半年卡', '年卡', '永久卡'];
    if (!durations.includes(duration) || !secrets.length || secrets.length > 500) return res.status(400).json({ message: '请选择有效时长，并导入 1 到 500 条卡密' });
    if (secrets.some(secret => secret.length > 300)) return res.status(400).json({ message: '单条卡密不能超过 300 个字符' });
    const { data: apps, error: appError } = await db.from('applications').select('id').eq('id', req.params.id).limit(1);
    if (appError) throw appError;
    if (!apps.length) return res.status(404).json({ message: '应用不存在' });
    const { error } = await db.from('card_keys').insert(secrets.map(secret => ({ application_id: req.params.id, duration, secret, status: 'available' })));
    if (error) {
      if (/duplicate|unique/i.test(String(error.message || error))) return res.status(409).json({ message: '导入失败：卡密已存在，请删除重复项后重试' });
      throw error;
    }
    res.status(201).json({ imported: secrets.length });
  } catch (error) { next(error); }
});

app.get('/api/admin/cards', auth('管理员'), async (req, res, next) => {
  try {
    const durations = ['小时卡', '天卡', '周卡', '月卡', '季卡', '半年卡', '年卡', '永久卡'];
    const statuses = ['available', 'sold'];
    const status = String(req.query.status || 'all');
    const duration = String(req.query.duration || 'all');
    if (status !== 'all' && !statuses.includes(status)) return res.status(400).json({ message: '库存状态无效' });
    if (duration !== 'all' && !durations.includes(duration)) return res.status(400).json({ message: '卡密时长无效' });
    let query = db.from('card_keys').select('id, application_id, duration, secret, status, sold_to, sold_at, created_at').order('created_at', { ascending: false });
    if (req.query.applicationId && req.query.applicationId !== 'all') query = query.eq('application_id', req.query.applicationId);
    if (status !== 'all') query = query.eq('status', status);
    if (duration !== 'all') query = query.eq('duration', duration);
    const { data, error } = await query;
    if (error) throw error;
    const ids = [...new Set(data.map(item => item.application_id))];
    const appNames = {};
    if (ids.length) {
      const { data: apps, error: appError } = await db.from('applications').select('id, name').in('id', ids);
      if (appError) throw appError;
      for (const item of apps) appNames[String(item.id)] = item.name;
    }
    res.set('Cache-Control', 'no-store');
    res.json({ cards: data.map(item => ({ id: item.id, applicationId: item.application_id, application: appNames[String(item.application_id)] || '已删除应用', duration: item.duration, secret: item.secret, status: item.status, soldAt: item.sold_at, createdAt: item.created_at })) });
  } catch (error) { next(error); }
});

app.delete('/api/admin/cards/:id', auth('管理员'), async (req, res, next) => {
  try {
    const { data, error } = await db.from('card_keys').delete().eq('id', req.params.id).eq('status', 'available').select('id');
    if (error) throw error;
    if (!data?.length) return res.status(404).json({ message: '未找到可删除的库存卡密；已售卡密不能删除' });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.post('/api/admin/cards/delete-batch', auth('管理员'), async (req, res, next) => {
  try {
    const ids = [...new Set((Array.isArray(req.body.ids) ? req.body.ids : []).map(id => String(id).trim()).filter(Boolean))];
    if (!ids.length || ids.length > 1000) return res.status(400).json({ message: '请选择 1 到 1000 条卡密' });
    const { data, error } = await db.from('card_keys').delete().in('id', ids).eq('status', 'available').select('id');
    if (error) throw error;
    res.json({ deleted: data?.length || 0, skipped: ids.length - (data?.length || 0) });
  } catch (error) { next(error); }
});

app.post('/api/cards/redeem', auth(), async (req, res, next) => {
  try {
    const applicationId = String(req.body.applicationId || '');
    const duration = String(req.body.duration || '');
    const { data: apps, error: appError } = await db.from('applications').select('id, name, prices').eq('id', applicationId).eq('status', 'active').limit(1);
    if (appError) throw appError;
    const application = apps[0];
    if (!application) return res.status(404).json({ message: '请选择有效应用' });
    const price = Number(application.prices?.[duration]);
    if (!Number.isFinite(price) || price < 0) return res.status(400).json({ message: '该时长暂未开放' });
    const user = await getUserById(req.user.id);
    if (!user || Number(user.balance) < price) return res.status(400).json({ message: '钱包余额不足，请联系管理员充值' });
    const { data: cards, error: cardError } = await db.from('card_keys').select('id, secret').eq('application_id', applicationId).eq('duration', duration).eq('status', 'available').limit(1);
    if (cardError) throw cardError;
    const card = cards[0];
    if (!card) return res.status(409).json({ message: '该应用和时长的卡密暂时缺货' });
    const claimed = await db.from('card_keys').update({ status: 'sold', sold_to: user.id, sold_at: new Date().toISOString() }).eq('id', card.id).eq('status', 'available').select('id');
    if (claimed.error) throw claimed.error;
    if (!claimed.data?.length) return res.status(409).json({ message: '卡密已被其他请求提取，请重试' });
    const charged = await usersTable().update({ balance: Number(user.balance) - price }).eq('id', user.id).eq('balance', user.balance).select('id');
    if (charged.error) {
      await db.from('card_keys').update({ status: 'available', sold_to: null, sold_at: null }).eq('id', card.id);
      throw charged.error;
    }
    if (!charged.data?.length) {
      await db.from('card_keys').update({ status: 'available', sold_to: null, sold_at: null }).eq('id', card.id);
      return res.status(409).json({ message: '余额已变化，请刷新后重试' });
    }
    res.json({ application: application.name, duration, price, balance: Number(user.balance) - price, cardKey: card.secret });
  } catch (error) { next(error); }
});

app.get('/api/cards/history', auth(), async (req, res, next) => {
  try {
    let query = db.from('card_keys').select('id, application_id, duration, secret, sold_at').eq('status', 'sold').eq('sold_to', req.user.id).order('sold_at', { ascending: false }).limit(200);
    if (req.query.applicationId && req.query.applicationId !== 'all') query = query.eq('application_id', req.query.applicationId);
    const { data, error } = await query;
    if (error) throw error;
    const ids = [...new Set(data.map(item => item.application_id))];
    let names = {};
    if (ids.length) {
      const { data: apps, error: appError } = await db.from('applications').select('id, name').in('id', ids);
      if (appError) throw appError;
      names = Object.fromEntries(apps.map(item => [String(item.id), item.name]));
    }
    res.set('Cache-Control', 'no-store');
    res.json({ records: data.map(item => ({ id: item.id, applicationId: item.application_id, application: names[String(item.application_id)] || '已删除应用', duration: item.duration, cardKey: item.secret, soldAt: item.sold_at })) });
  } catch (error) { next(error); }
});

app.post('/api/users', auth('管理员'), async (req, res, next) => {
  try {
    const { name, email, password, role = '成员', department = '', status = 'active' } = req.body;
    if (!name || !email || !password || password.length < 6) return res.status(400).json({ message: '姓名、邮箱和至少6位密码不能为空' });
    if (await getUserByEmail(email.trim().toLowerCase())) return res.status(409).json({ message: '该邮箱已注册' });
    const { data, error } = await usersTable().insert({ name: name.trim(), email: email.trim().toLowerCase(), password_hash: await bcrypt.hash(password, 12), role, department: department.trim(), status }).select();
    if (error) throw error;
    res.status(201).json({ user: publicUser(data[0]) });
  } catch (error) { next(error); }
});

app.put('/api/users/:id', auth('管理员'), async (req, res, next) => {
  try {
    const { name, email, password, role, department, status } = req.body;
    if (!name || !email || !role || department === undefined || !['active', 'inactive'].includes(status)) return res.status(400).json({ message: '用户资料不完整' });
    if (password && password.length < 6) return res.status(400).json({ message: '密码至少需要 6 位' });
    const duplicate = await getUserByEmail(email.trim().toLowerCase());
    if (duplicate && String(duplicate.id) !== String(req.params.id)) return res.status(409).json({ message: '该邮箱已注册' });
    const changes = { name: name.trim(), email: email.trim().toLowerCase(), role, department: department.trim(), status };
    if (password) changes.password_hash = await bcrypt.hash(password, 12);
    const { error } = await usersTable().update(changes).eq('id', req.params.id);
    if (error) throw error;
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ message: '用户不存在' });
    res.json({ user: publicUser(user) });
  } catch (error) { next(error); }
});

app.delete('/api/users/:id', auth('管理员'), async (req, res, next) => {
  try {
    if (String(req.user.id) === String(req.params.id)) return res.status(400).json({ message: '不能删除当前登录管理员' });
    const { error } = await usersTable().delete().eq('id', req.params.id);
    if (error) throw error;
    res.status(204).end();
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (/platform_settings.*does not exist|relation .* does not exist/i.test(String(error.message || ''))) {
    return res.status(503).json({ message: '数据库缺少系统设置表，请在 CloudBase PostgreSQL 执行最新 schema.sql 后重试' });
  }
  res.status(500).json({ message: '服务器内部错误' });
});

async function bootstrap() {
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const existing = await getUserByEmail(adminEmail);
  if (!existing) {
    const password = process.env.ADMIN_PASSWORD;
    if (!password || password.length < 6) throw new Error('首次启动必须在 .env 配置 ADMIN_PASSWORD，且至少 6 位');
    const { error } = await usersTable().insert({ name: process.env.ADMIN_NAME || '管理员', email: adminEmail, password_hash: await bcrypt.hash(password, 12), role: '管理员', department: '管理部', status: 'active' });
    if (error) throw error;
    console.log(`已创建首个管理员：${adminEmail}`);
  }
  app.listen(port, () => console.log(`森序管理平台运行于 http://localhost:${port}`));
}

bootstrap().catch(error => { console.error('启动失败：', error.message || error); process.exit(1); });
