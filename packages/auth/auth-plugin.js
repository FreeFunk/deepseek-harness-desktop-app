import { DatabaseSync } from "node:sqlite";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { mkdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { serveStatic } from "@deepseek-ai/dsh-host-frontend-static";
import z from "@deepseek-ai/schemastery";

export const name = "auth";
export const inject = ["webServer"];

export const Config = z.object({
  distIndex: z.string().required(),
});

const dshHome = join(homedir(), ".dsh");
mkdirSync(dshHome, { recursive: true });
const dbPath = join(dshHome, "auth.db");

const db = new DatabaseSync(dbPath);
db.exec("PRAGMA journal_mode=WAL");
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)`);
db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS menus (
  key TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  parent TEXT,
  roles TEXT NOT NULL DEFAULT 'admin,user',
  "order" INTEGER NOT NULL DEFAULT 0
)`);

const uc = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
if (uc === 0) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync("admin123", salt, 64).toString("hex");
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)").run("admin", salt + ":" + hash, "admin");
  const menus = [
    ["chat", "对话", null, "admin,user", 1],
    ["sessions", "会话历史", null, "admin,user", 2],
    ["settings", "设置", null, "admin", 3],
    ["user-management", "用户管理", null, "admin", 4],
    ["tools", "工具", null, "admin,user", 5],
  ];
  const im = db.prepare('INSERT OR IGNORE INTO menus (key, label, parent, roles, "order") VALUES (?, ?, ?, ?, ?)');
  for (const m of menus) im.run(...m);
}

function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const c = scryptSync(pw, salt, 64);
  const e = Buffer.from(hash, "hex");
  return c.length === e.length && timingSafeEqual(c, e);
}

function getUser(cookie) {
  if (!cookie) return null;
  const m = cookie.match(/dsh_token=([^;]+)/);
  if (!m) return null;
  const s = db.prepare("SELECT * FROM sessions WHERE token = ?").get(m[1]);
  if (!s || new Date(s.expires_at) < new Date()) return null;
  return db.prepare("SELECT id, username, role FROM users WHERE id = ?").get(s.user_id) || null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = ""; req.on("data", c => d += c); req.on("end", () => resolve(d)); req.on("error", reject);
  });
}

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
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
<button class="btn">登录</button>
</form>
<div id="e" class="err"></div>
</div>
<script>
document.getElementById("f").addEventListener("submit",async function(e){e.preventDefault();var x=document.getElementById("e");x.classList.remove("show");try{var r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})});if(!r.ok){var d=await r.json();x.textContent=d.error||"登录失败";x.classList.add("show");return}window.location.href="/"}catch(err){x.textContent="网络错误";x.classList.add("show")}})
</script>
</body>
</html>`;

export function apply(ctx, config) {
  const distIndex = config.distIndex;
  const distRoot = dirname(distIndex);
  const renderIndex = async () => ctx.webServer.applyIndexTaps(await readFile(distIndex, "utf8"));

  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "exact",
      path: "/login",
      handler: (req, res) => {
        const user = getUser(req.headers.cookie);
        if (user) {
          res.writeHead(302, { Location: "/" });
          res.end();
          return;
        }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(LOGIN_HTML);
      }
    });
  }, "auth: 登录页");

  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "exact",
      path: "/api/auth/login",
      handler: async (req, res) => {
        if (req.method !== "POST") { json(res, 405, { error: "Method not allowed" }); return; }
        try {
          const body = JSON.parse(await readBody(req));
          const user = db.prepare("SELECT * FROM users WHERE username = ?").get(body.username);
          if (!user || !verifyPassword(body.password, user.password_hash)) {
            json(res, 401, { error: "用户名或密码错误" }); return;
          }
          const token = randomUUID();
          db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").run(
            token, user.id, new Date(Date.now() + 86400000).toISOString()
          );
          res.writeHead(200, {
            "Content-Type": "application/json; charset=utf-8",
            "Set-Cookie": "dsh_token=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
          });
          res.end(JSON.stringify({ token, user: { id: user.id, username: user.username, role: user.role } }));
        } catch (e) { json(res, 400, { error: e.message }); }
      }
    });
  }, "auth: 登录接口");

  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "exact",
      path: "/api/auth/logout",
      handler: (req, res) => {
        const m = (req.headers.cookie || "").match(/dsh_token=([^;]+)/);
        if (m) db.prepare("DELETE FROM sessions WHERE token = ?").run(m[1]);
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "dsh_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        });
        res.end(JSON.stringify({ ok: true }));
      }
    });
  }, "auth: 登出");

  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "exact",
      path: "/api/auth/me",
      handler: (req, res) => {
        const u = getUser(req.headers.cookie);
        if (!u) { json(res, 401, { error: "未登录" }); return; }
        json(res, 200, u);
      }
    });
  }, "auth: 当前用户");

  ctx.effect(() => {
    return ctx.webServer.register({
      kind: "exact",
      path: "/api/auth/menus",
      handler: (req, res) => {
        const u = getUser(req.headers.cookie);
        if (!u) { json(res, 401, { error: "未登录" }); return; }
        const all = db.prepare('SELECT * FROM menus ORDER BY "order"').all();
        const menus = all.filter(m => m.roles.split(",").includes(u.role)).map(m => ({
          key: m.key, label: m.label, parent: m.parent, roles: m.roles.split(","), order: m.order
        }));
        json(res, 200, menus);
      }
    });
  }, "auth: 菜单权限");

  ctx.effect(() => ctx.webServer.registerFallback(async (req, res) => {
    const rawPath = new URL(req.url ?? "/", "http://x").pathname;
    const user = getUser(req.headers.cookie);

    if (!user) {
      if (rawPath.startsWith("/api/")) {
        json(res, 401, { error: "未登录" });
        return;
      }
      const accept = req.headers.accept || "";
      if (accept.includes("text/html")) {
        res.writeHead(302, { Location: "/login" });
        res.end();
        return;
      }
      res.writeHead(401, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "未登录" }));
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405);
      res.end();
      return;
    }
    await serveStatic(decodeURIComponent(rawPath), res, distRoot, distIndex, renderIndex);
  }), "auth: 兜底拦截");
}