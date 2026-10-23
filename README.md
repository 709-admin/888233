# 森序管理平台

## 本地启动

1. 安装 Node.js 18+，并在 CloudBase 开通 PostgreSQL 实例。
2. 在 CloudBase 控制台的 SQL 编辑器执行 `schema.sql`，创建 `public.users` 表。
3. 在 CloudBase API Key 管理中创建服务端 API Key，复制 `.env.example` 为 `.env`，填写环境 ID、API Key、JWT_SECRET 和首个管理员密码。
4. 执行 `npm install`。
5. 执行 `npm start`。
6. 浏览器打开 `http://localhost:3000`。

首个管理员账号使用 `.env` 中的 `ADMIN_EMAIL` 和 `ADMIN_PASSWORD`。登录后在用户管理页新增其他账户。

启动后服务会自动创建首个管理员；表结构需要先在 CloudBase SQL 编辑器执行。当前后端已包含登录、用户列表、新增、编辑和删除 API。正式上线前还应配置 HTTPS、限制 CORS 来源、修改默认管理员密码并定期备份数据库。
