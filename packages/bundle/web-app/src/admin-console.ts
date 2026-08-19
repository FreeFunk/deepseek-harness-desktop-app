/**
 * Self-contained admin console page served by the auth plugin at `/admin`.
 * Plain HTML/CSS/JS with no build step or framework, so it runs wherever the
 * plugin runs. Access is gated twice: the transport guard requires a session,
 * and the `/admin` route handler refuses users without the `page:admin`
 * permission. The page talks only to the `/api/auth/*` JSON surface.
 * @module @deepseek-ai/dsh-web-app/admin-console
 */

/** The full `/admin` document (a single-file SPA with three tabs). */
export const ADMIN_CONSOLE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理控制台 - DeepSeek Harness</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px}
header h1{font-size:22px;color:#f0f6fc}
header .user{display:flex;align-items:center;gap:10px;font-size:13px;color:#8b949e}
button{font:inherit;cursor:pointer}
nav{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid #30363d}
nav button{background:none;border:none;color:#8b949e;padding:10px 16px;font-size:14px;border-bottom:2px solid transparent}
nav button.active{color:#f0f6fc;border-bottom-color:#58a6ff}
.panel{display:none}
.panel.active{display:block}
.toolbar{display:flex;justify-content:flex-end;margin-bottom:12px;gap:8px}
.btn{background:#238636;border:1px solid rgba(240,246,252,0.1);color:#fff;padding:7px 14px;border-radius:6px;font-size:13px}
.btn.secondary{background:#21262d;color:#c9d1d9}
.btn.danger{background:#da3633}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn:hover:not(:disabled){filter:brightness(1.1)}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;font-size:13px;border-bottom:1px solid #21262d;vertical-align:middle}
th{background:#21262d;color:#8b949e;font-weight:600}
tr:last-child td{border-bottom:none}
td .ops{display:flex;gap:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px}
.badge.ok{background:rgba(63,185,80,0.15);color:#3fb950}
.badge.off{background:rgba(248,81,73,0.15);color:#f85149}
.empty{color:#8b949e;font-size:13px;padding:20px;text-align:center}
.modal{position:fixed;inset:0;background:rgba(1,4,9,0.7);display:none;align-items:flex-start;justify-content:center;padding:60px 16px;z-index:50}
.modal.open{display:flex}
.modal .card{background:#161b22;border:1px solid #30363d;border-radius:10px;width:460px;max-width:100%;padding:20px;max-height:80vh;overflow:auto}
.modal h3{font-size:16px;color:#f0f6fc;margin-bottom:16px}
.fg{margin-bottom:14px}
.fg label{display:block;font-size:13px;color:#c9d1d9;margin-bottom:6px}
.fg input,.fg select,.fg textarea{width:100%;padding:9px 11px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#f0f6fc;font-size:13px}
.fg textarea{resize:vertical;min-height:60px}
.actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.roles{display:grid;grid-template-columns:240px 1fr;gap:16px}
.role-list{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.role-item{padding:10px 12px;cursor:pointer;border-bottom:1px solid #21262d;font-size:13px;color:#c9d1d9}
.role-item:last-child{border-bottom:none}
.role-item.active{background:#1f6feb;color:#fff}
.role-item small{display:block;color:#8b949e;font-size:12px;margin-top:2px}
.role-item.active small{color:rgba(255,255,255,0.75)}
.role-detail{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.role-detail h3{font-size:15px;color:#f0f6fc;margin-bottom:4px}
.role-detail .desc{color:#8b949e;font-size:12px;margin-bottom:14px}
.perm-group{margin-bottom:14px}
.perm-group h4{font-size:12px;color:#8b949e;margin-bottom:8px;letter-spacing:.04em;text-transform:uppercase}
.perm{display:flex;align-items:center;gap:8px;padding:7px 9px;border:1px solid #30363d;border-radius:6px;margin-bottom:6px;font-size:13px}
.perm input{accent-color:#1f6feb}
.perm .pdesc{color:#8b949e;font-size:12px;margin-left:auto}
.msg{position:fixed;top:16px;left:50%;transform:translateX(-50%);padding:10px 16px;border-radius:8px;font-size:13px;z-index:100;display:none;white-space:nowrap}
.msg.show{display:block}
.msg.ok{background:#1f6feb;color:#fff}
.msg.err{background:#da3633;color:#fff}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>管理控制台</h1>
    <div class="user"><span id="user-name"></span><button class="btn secondary" id="logout-btn">退出登录</button></div>
  </header>
  <nav>
    <button data-tab="users" class="active">用户管理</button>
    <button data-tab="roles">角色权限</button>
    <button data-tab="password">修改密码</button>
  </nav>
  <section id="tab-users" class="panel active">
    <div class="toolbar"><button class="btn" id="new-user-btn">新建用户</button></div>
    <div id="users-table"></div>
  </section>
  <section id="tab-roles" class="panel">
    <div class="toolbar"><button class="btn" id="new-role-btn">新建角色</button><button class="btn secondary" id="save-role-btn">保存权限</button></div>
    <div class="roles">
      <div id="role-list" class="role-list"></div>
      <div id="role-detail" class="role-detail"></div>
    </div>
  </section>
  <section id="tab-password" class="panel">
    <div class="role-detail" style="max-width:460px">
      <h3>修改登录密码</h3>
      <div class="desc">修改后下次登录请使用新密码。</div>
      <div class="fg"><label>当前密码</label><input type="password" id="pw-current"></div>
      <div class="fg"><label>新密码</label><input type="password" id="pw-new"></div>
      <div class="fg"><label>确认新密码</label><input type="password" id="pw-confirm"></div>
      <div class="actions"><button class="btn" id="pw-save">保存</button></div>
    </div>
  </section>
</div>
<div id="modal" class="modal"><div class="card" id="modal-card"></div></div>
<div id="msg" class="msg"></div>
<script>
(function(){
  function $(s){ return document.querySelector(s) }
  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c] }) }
  var me = null
  var roles = []
  var perms = []
  var selectedRoleId = null
  function api(path, opts){
    opts = opts || {}
    opts.headers = opts.headers || {}
    opts.headers['Content-Type'] = 'application/json'
    opts.credentials = 'same-origin'
    return fetch(path, opts).then(function(r){
      if (r.status === 401){ location.href = '/login'; throw new Error('unauthorized') }
      return r.json().then(function(d){
        if (!r.ok){ throw new Error(d && d.error ? d.error : ('HTTP ' + r.status)) }
        return d
      })
    })
  }
  function msg(text, ok){
    var m = $('#msg')
    m.textContent = text
    m.className = 'msg show ' + (ok ? 'ok' : 'err')
    clearTimeout(msg._t)
    msg._t = setTimeout(function(){ m.className = 'msg' }, 3000)
  }
  function modal(html){
    $('#modal-card').innerHTML = html
    $('#modal').className = 'modal open'
  }
  function closeModal(){ $('#modal').className = 'modal' }
  function statusBadge(st){ return st === 1 ? '<span class="badge ok">启用</span>' : '<span class="badge off">停用</span>' }
  function roleName(id){
    for (var i = 0; i < roles.length; i++) if (roles[i].id === id) return roles[i].label
    return String(id)
  }
  function switchTab(name){
    var tabs = ['users','roles','password']
    for (var i = 0; i < tabs.length; i++){
      var on = tabs[i] === name
      $('#tab-' + tabs[i]).className = 'panel' + (on ? ' active' : '')
      var b = document.querySelector('nav button[data-tab="' + tabs[i] + '"]')
      if (b) b.className = on ? 'active' : ''
    }
  }
  function loadUsers(){
    api('/api/auth/users').then(function(d){
      dshUsers = d.users
      var rows = d.users.map(function(u){
        return '<tr><td>' + esc(u.id) + '</td><td>' + esc(u.username) + '</td><td>' + esc(u.displayName) + '</td>'
          + '<td>' + esc(u.roleLabel) + '</td><td>' + statusBadge(u.status) + '</td><td>' + esc(u.createdAt) + '</td>'
          + '<td><div class="ops"><button class="btn secondary" data-op="edit" data-id="' + u.id + '">编辑</button>'
          + '<button class="btn secondary" data-op="reset" data-id="' + u.id + '">重置密码</button>'
          + (u.username !== me.username ? '<button class="btn danger" data-op="del" data-id="' + u.id + '">删除</button>' : '')
          + '</div></td></tr>'
      }).join('')
      $('#users-table').innerHTML = '<table><thead><tr><th>ID</th><th>用户名</th><th>显示名</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>'
        + (rows || '<tr><td colspan="7" class="empty">暂无用户</td></tr>') + '</tbody></table>'
    }).catch(function(e){ msg(e.message, false) })
  }
  function userModal(mode, user){
    var roleOpts = roles.map(function(r){ return '<option value="' + r.id + '"' + (user && user.roleId === r.id ? ' selected' : '') + '>' + esc(r.label) + '</option>' }).join('')
    modal('<h3>' + (mode === 'create' ? '新建用户' : '编辑用户') + '</h3>'
      + (mode === 'create'
        ? '<div class="fg"><label>用户名</label><input id="m-username" autocomplete="off"></div>'
        : '<div class="fg"><label>用户名</label><input id="m-username" value="' + esc(user.username) + '" disabled></div>')
      + '<div class="fg"><label>显示名</label><input id="m-display" value="' + (user ? esc(user.displayName) : '') + '"></div>'
      + '<div class="fg"><label>角色</label><select id="m-role">' + roleOpts + '</select></div>'
      + '<div class="fg"><label>状态</label><select id="m-status">'
      + '<option value="1"' + (!user || user.status === 1 ? ' selected' : '') + '>启用</option>'
      + '<option value="0"' + (user && user.status === 0 ? ' selected' : '') + '>停用</option></select></div>'
      + (mode === 'create' ? '<div class="fg"><label>初始密码</label><input id="m-password" type="password"></div>' : '')
      + '<div class="actions"><button class="btn secondary" id="m-cancel">取消</button><button class="btn" id="m-save">保存</button></div>')
    $('#m-cancel').onclick = closeModal
    $('#m-save').onclick = function(){
      var body = { displayName: $('#m-display').value, roleId: Number($('#m-role').value), status: Number($('#m-status').value) }
      if (mode === 'create'){ body.username = $('#m-username').value.trim(); body.password = $('#m-password').value }
      var p = mode === 'create' ? api('/api/auth/users', { method: 'POST', body: JSON.stringify(body) })
        : api('/api/auth/users/' + user.id, { method: 'PATCH', body: JSON.stringify(body) })
      p.then(function(){ closeModal(); msg(mode === 'create' ? '用户已创建' : '用户已更新', true); loadUsers() })
        .catch(function(e){ msg(e.message, false) })
    }
  }
  function loadRoles(){
    Promise.all([api('/api/auth/roles'), api('/api/auth/permissions')]).then(function(res){
      roles = res[0].roles
      perms = res[1].permissions
      if (selectedRoleId == null && roles.length) selectedRoleId = roles[0].id
      renderRoleList()
      renderRoleDetail()
    }).catch(function(e){ msg(e.message, false) })
  }
  function renderRoleList(){
    $('#role-list').innerHTML = roles.map(function(r){
      return '<div class="role-item' + (r.id === selectedRoleId ? ' active' : '') + '" data-id="' + r.id + '">'
        + esc(r.label) + (r.isSystem ? ' <span style="opacity:.6">(系统)</span>' : '')
        + '<small>' + esc(r.name) + (r.permissions.length ? ' · ' + r.permissions.length + ' 项权限' : '') + '</small></div>'
    }).join('')
    var items = document.querySelectorAll('#role-list .role-item')
    for (var i = 0; i < items.length; i++) items[i].onclick = function(){ selectedRoleId = Number(this.dataset.id); renderRoleList(); renderRoleDetail() }
  }
  function renderRoleDetail(){
    var role = null
    for (var i = 0; i < roles.length; i++) if (roles[i].id === selectedRoleId) role = roles[i]
    if (!role){ $('#role-detail').innerHTML = '<div class="empty">请选择角色</div>'; return }
    var groups = { page: [], api: [] }
    for (var j = 0; j < perms.length; j++){
      var g = perms[j].group === 'api' ? 'api' : 'page'
      groups[g].push(perms[j])
    }
    function groupHtml(perms, label){
      if (!perms.length) return ''
      return '<div class="perm-group"><h4>' + label + '</h4>' + perms.map(function(p){
        var checked = role.permissions.indexOf(p.key) >= 0
        return '<label class="perm"><input type="checkbox" data-key="' + esc(p.key) + '"' + (checked ? ' checked' : '') + '>'
          + '<span>' + esc(p.label) + '</span><span class="pdesc">' + esc(p.description) + '</span></label>'
      }).join('') + '</div>'
    }
    $('#role-detail').innerHTML = '<h3>' + esc(role.label) + '</h3><div class="desc">' + esc(role.description)
      + (role.isSystem ? ' · 系统角色不可删除' : '') + '</div>'
      + groupHtml(groups.page, '页面权限') + groupHtml(groups.api, '接口权限')
      + '<div class="actions">' + (role.isSystem ? '' : '<button class="btn danger" id="role-del">删除角色</button>') + '</div>'
    var del = $('#role-del')
    if (del) del.onclick = function(){
      if (!confirm('确定删除角色 ' + role.name + ' ？')) return
      api('/api/auth/roles/' + role.id, { method: 'DELETE' }).then(function(){
        selectedRoleId = null; msg('角色已删除', true); loadRoles()
      }).catch(function(e){ msg(e.message, false) })
    }
  }
  function saveSelectedRole(){
    var role = null
    for (var i = 0; i < roles.length; i++) if (roles[i].id === selectedRoleId) role = roles[i]
    if (!role) return
    var checked = []
    var boxes = document.querySelectorAll('#role-detail input[type="checkbox"]')
    for (var j = 0; j < boxes.length; j++) if (boxes[j].checked) checked.push(boxes[j].dataset.key)
    api('/api/auth/roles/' + role.id, { method: 'PATCH', body: JSON.stringify({ label: role.label, description: role.description, permissions: checked }) })
      .then(function(){ msg('权限已保存', true); loadRoles() })
      .catch(function(e){ msg(e.message, false) })
  }
  function roleModal(){
    modal('<h3>新建角色</h3>'
      + '<div class="fg"><label>角色标识</label><input id="r-name" placeholder="如 reviewer"></div>'
      + '<div class="fg"><label>显示名</label><input id="r-label"></div>'
      + '<div class="fg"><label>描述</label><textarea id="r-desc"></textarea></div>'
      + '<div class="actions"><button class="btn secondary" id="m-cancel">取消</button><button class="btn" id="r-save">创建</button></div>')
    $('#m-cancel').onclick = closeModal
    $('#r-save').onclick = function(){
      api('/api/auth/roles', { method: 'POST', body: JSON.stringify({ name: $('#r-name').value.trim(), label: $('#r-label').value.trim(), description: $('#r-desc').value.trim() }) })
        .then(function(d){ closeModal(); selectedRoleId = d.role.id; msg('角色已创建', true); loadRoles() })
        .catch(function(e){ msg(e.message, false) })
    }
  }
  function passwordSave(){
    var cur = $('#pw-current').value, nw = $('#pw-new').value, cf = $('#pw-confirm').value
    if (!nw || nw.length < 6){ msg('新密码至少 6 位', false); return }
    if (nw !== cf){ msg('两次输入的新密码不一致', false); return }
    api('/api/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword: cur, newPassword: nw }) })
      .then(function(){ msg('密码已修改', true); $('#pw-current').value = $('#pw-new').value = $('#pw-confirm').value = '' })
      .catch(function(e){ msg(e.message, false) })
  }
  document.addEventListener('click', function(e){
    var t = e.target
    if (t && t.dataset && t.dataset.tab){ switchTab(t.dataset.tab); return }
    if (t && t.id === 'logout-btn'){
      fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(function(){ location.href = '/login' }).catch(function(){ location.href = '/login' })
      return
    }
    if (t && t.dataset && t.dataset.op){
      var id = Number(t.dataset.id)
      var user = null
      var u = dshUsers || []
      for (var i = 0; i < u.length; i++) if (u[i].id === id) user = u[i]
      if (t.dataset.op === 'edit'){ userModal('edit', user); return }
      if (t.dataset.op === 'del'){ if (!confirm('确定删除用户 ' + (user ? user.username : id) + ' ？')) return; api('/api/auth/users/' + id, { method: 'DELETE' }).then(function(){ msg('用户已删除', true); loadUsers() }).catch(function(x){ msg(x.message, false) }); return }
      if (t.dataset.op === 'reset'){
        var pw = prompt('输入新的登录密码')
        if (pw == null) return
        api('/api/auth/users/' + id, { method: 'PATCH', body: JSON.stringify({ password: pw }) }).then(function(){ msg('密码已重置', true) }).catch(function(x){ msg(x.message, false) })
      }
    }
  })
  api('/api/auth/users').then(function(){})
  $('#new-user-btn').onclick = function(){ userModal('create', null) }
  $('#new-role-btn').onclick = roleModal
  $('#save-role-btn').onclick = saveSelectedRole
  $('#pw-save').onclick = passwordSave
  api('/api/auth/me').then(function(d){
    me = d
    $('#user-name').textContent = d.username + (d.role ? ' · ' + d.role.label : '')
    if (!d.permissions || d.permissions.indexOf('page:admin') < 0){
      document.querySelector('.wrap').innerHTML = '<div class="empty" style="padding:60px 0">没有管理权限，无法访问控制台</div>'
      return
    }
    loadUsers()
    loadRoles()
  }).catch(function(){})
  window.addEventListener('keydown', function(e){ if (e.key === 'Escape') closeModal() })
})()
</script>
</body>
</html>`
