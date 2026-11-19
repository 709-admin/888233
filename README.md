# 森序管理平台

## Ubuntu 部署

本项目使用本机 PostgreSQL，不再依赖 CloudBase。

1. 安装 PostgreSQL：`sudo apt update && sudo apt install -y postgresql`
2. 创建数据库用户和数据库：

   ```bash
   sudo -u postgres psql -c "CREATE USER admin709 WITH PASSWORD '替换为仅含字母数字的高强度密码';"
   sudo -u postgres psql -c "CREATE DATABASE admin709 OWNER admin709;"
   ```

3. 在项目根目录执行表结构初始化。将命令中的密码替换为上一步设置的密码：

   ```bash
   PGPASSWORD='数据库密码' psql -h 127.0.0.1 -U admin709 -d admin709 -f schema.sql
   ```

4. 复制 `.env.example` 为 `.env`，填写数据库连接、JWT 密钥和首个管理员信息：

   ```env
   PORT=3000
   DATABASE_URL=postgresql://admin709:数据库密码@127.0.0.1:5432/admin709
   JWT_SECRET=至少32位的随机字符串
   ADMIN_NAME=Administrator
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=至少6位的管理员密码
   ```

5. 安装依赖并启动：

   ```bash
   npm install
   npm start
   ```

6. 验证服务：`curl http://127.0.0.1:3000/api/health`，浏览器访问 `http://服务器IP:3000`。

首个管理员账号使用 `.env` 中的 `ADMIN_EMAIL` 和 `ADMIN_PASSWORD`。登录后在用户管理页新增其他账户。

启动后服务会自动创建首个管理员。正式上线前还应配置 PM2、Nginx 和 HTTPS，限制 CORS 来源，修改默认管理员密码，并定期备份数据库。
****
