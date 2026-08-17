import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { DatabaseSync } from "node:sqlite";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

const dshHome = join(homedir(), ".dsh");
mkdirSync(dshHome, { recursive: true });

const DB_PATH = process.env.AUTH_DB_PATH || join(dshHome, "auth.db");
const PORT = parseInt(process.env.AUTH_PORT || "3080", 10);
const HOST = process.env.AUTH_HOST || "0.0.0.0";
const BACKEND = process.env.BACKEND_URL || "http://127.0.0.1:3099";
const ADMIN_USER = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASS = process.env.ADMIN_PASSWORD || "admin123";

// ========== Database ==========
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode=WAL");
db.exec("PRAGMA foreign_keys=ON");
db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL DEFAULT (datetime('now')))");
db.exec("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT NOT NULL)");
db.exec("CREATE TABLE IF NOT EXISTS menus (key TEXT PRIMARY KEY, label TEXT NOT NULL, parent TEXT, roles TEXT NOT NULL DEFAULT 'admin,user', \"order\" INTEGER NOT NULL DEFAULT 0)");

const userCount = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
if (userCount === 0) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(ADMIN_PASS, salt, 64).toString("hex");
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)").run(ADMIN_USER, salt + ":" + hash, "admin");
  const menus = [
    ["chat", "对话", null, "admin,user", 1],
    ["sessions", "会话历史", null, "admin,user", 2],
    ["settings", "设置", null, "admin", 3],
    ["user-management", "用户管理", null, "admin", 4],
    ["tools", "工具", null, "admin,user", 5],
  ];
  const insertMenu = db.prepare("INSERT OR IGNORE INTO menus (key, label, parent, roles, \"order\") VALUES (?, ?, ?, ?, ?)");
  for (const m of menus) insertMenu.run(...m);
}

function hashPassword(pw) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(pw, salt, 64).toString("hex");
  return salt + ":" + hash;
}

function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const computed = scryptSync(pw, salt, 64);
  const expected = Buffer.from(hash, "hex");
  if (computed.length !== expected.length) return false;
  return timingSafeEqual(computed, expected);
}

function getUserFromCookie(cookie) {
  if (!cookie) return null;
  const m = cookie.match(/dsh_token=([^;]+)/);
  if (!m) return null;
  const session = db.prepare("SELECT * FROM sessions WHERE token = ?").get(m[1]);
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(m[1]);
    return null;
  }
  return db.prepare("SELECT id, username, role FROM users WHERE id = ?").get(session.user_id) || null;
}

function getMenus(userId) {
  const user = db.prepare("SELECT role FROM users WHERE id = ?").get(userId);
  if (!user) return [];
  const all = db.prepare("SELECT * FROM menus ORDER BY \"order\"").all();
  return all.filter(function(m) { return m.roles.split(",").includes(user.role); }).map(function(m) {
    return { key: m.key, label: m.label, parent: m.parent, roles: m.roles.split(","), order: m.order };
  });
}

// ========== Login Page HTML ==========
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - DeepSeek Harness</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:380px;max-width:90vw}
.box h1{font-size:24px;margin-bottom:8px;color:#f0f6fc;text-align:center}
.box p{color:#8b949e;font-size:14px;margin-bottom:24px;text-align:center}
.fg{margin-bottom:16px}
.fg label{display:block;font-size:13px;color:#c9d1d9;margin-bottom:6px}
.fg input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px;outline:none}
.fg input:focus{border-color:#58a6ff}
.btn{width:100%;padding:10px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin-top:8px}
.btn:hover{background:#2ea043}
.err{color:#f85149;font-size:13px;text-align:center;margin-top:12px;display:none}
.err.show{display:block}
</style>
</head>
<body>
<div class="box">
<h1>DeepSeek Harness</h1>
<p>请输入用户名和密码登录</p>
<form id="f">
<div class="fg"><label>用户名</label><input type="text" id="u" autocomplete="username" required autofocus></div>
<div class="fg"><label>密码</label><input type="password" id="p" autocomplete="current-password" required></div>
<button class="btn">登 录</button>
</form>
<div id="e" class="err"></div>
</div>
<script>
document.getElementById("f").addEventListener("submit",async function(e){e.preventDefault();var x=document.getElementById("e");x.classList.remove("show");try{var r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})});if(!r.ok){var d=await r.json();x.textContent=d.error||"登录失败";x.classList.add("show");return}window.location.href="/"}catch(err){x.textContent="网络错误";x.classList.add("show")}})
</script>
</body>
</html>`;

// ========== HTTP Handlers ==========
function readBody(req) {
  return new Promise(function(resolve, reject) {
    var data = "";
    req.on("data", function(c) { data += c; });
    req.on("end", function() { resolve(data); });
    req.on("error", reject);
  });
}

function proxyToBackend(req, res) {
  var target = new URL(req.url, BACKEND);
  var opts = {
    method: req.method,
    headers: req.headers,
    hostname: target.hostname,
    port: target.port,
    path: target.pathname + target.search,
  };
  delete opts.headers.host;
  var proto = target.protocol === "https:" ? httpsRequest : httpRequest;
  var proxyReq = proto.request(opts, function(proxyRes) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on("error", function() {
    res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("后端服务不可用");
  });
  req.pipe(proxyReq);
}

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

const server = createServer(async function(req, res) {
  var url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  var path = url.pathname;

  if (path === "/login" || path === "/login.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(LOGIN_HTML);
    return;
  }

  if (path === "/api/auth/login" && req.method === "POST") {
    try {
      var body = JSON.parse(await readBody(req));
      if (!body.username || !body.password) return json(res, 400, { error: "用户名和密码不能为空" });
      var user = db.prepare("SELECT * FROM users WHERE username = ?").get(body.username);
      if (!user || !verifyPassword(body.password, user.password_hash)) {
        return json(res, 401, { error: "用户名或密码错误" });
      }
      var token = randomUUID();
      var expires = new Date(Date.now() + 24 * 3600000).toISOString();
      db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").run(token, user.id, expires);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": "dsh_token=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
      });
      res.end(JSON.stringify({ token: token, user: { id: user.id, username: user.username, role: user.role } }));
    } catch (e) {
      json(res, 400, { error: e.message });
    }
    return;
  }

  if (path === "/api/auth/logout" && req.method === "POST") {
    var m = (req.headers.cookie || "").match(/dsh_token=([^;]+)/);
    if (m) db.prepare("DELETE FROM sessions WHERE token = ?").run(m[1]);
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": "dsh_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (path === "/api/auth/me") {
    var user = getUserFromCookie(req.headers.cookie);
    if (!user) return json(res, 401, { error: "未登录" });
    return json(res, 200, user);
  }

  if (path === "/api/auth/menus") {
    var user = getUserFromCookie(req.headers.cookie);
    if (!user) return json(res, 401, { error: "未登录" });
    return json(res, 200, getMenus(user.id));
  }

  var user = getUserFromCookie(req.headers.cookie);
  if (!user) {
    if (path.startsWith("/api/")) return json(res, 401, { error: "未登录" });
    res.writeHead(302, { Location: "/login" });
    res.end();
    return;
  }

  proxyToBackend(req, res);
});

server.listen(PORT, HOST, function() {
  console.log("[auth] 服务已启动 http://" + HOST + ":" + PORT);
  console.log("[auth] 后端: " + BACKEND);
  console.log("[auth] 管理员: " + ADMIN_USER);
});

process.on("SIGINT", function() { db.close(); server.close(); process.exit(0); });
process.on("SIGTERM", function() { db.close(); server.close(); process.exit(0); });