/**
 * Script injected into the served SPA `index.html` through the webserver
 * index tap. It surfaces the signed-in user (a corner chip with a menu for the
 * admin console, password change, and logout), redirects an expired session to
 * `/login`, exposes the session as `window.__DSH_AUTH__`, and hides
 * `[data-dsh-page]` elements whose page permission the current user lacks
 * (the page-control hook; the server enforces access regardless).
 *
 * The body is a plain <script> — it must not contain the literal sequence
 * `</script>`, so it is split below into `ESCAPED_END_TAG` never emitted by
 * this module; the only script-closing sequence in the emitted HTML is the
 * real one at the end.
 * @module @deepseek-ai/dsh-web-app/bootstrap
 */

/** The `<script>` body injected before the end of the SPA `<head>`. */
export const AUTH_BOOTSTRAP_SCRIPT = `(function(){
  var ORIGINAL = window.fetch ? window.fetch.bind(window) : null
  if (ORIGINAL){
    window.fetch = function(input, init){
      return ORIGINAL(input, init).then(function(res){
        var url = typeof input === 'string' ? input : (input && input.url ? input.url : '')
        if (res.status === 401 && url.indexOf('/api/') === 0 && url.indexOf('/api/auth/login') !== 0){
          try { location.href = '/login' } catch (e) { /* navigation in progress */ }
        }
        return res
      })
    }
  }
  function fetchJSON(url){
    return fetch(url, { credentials: 'same-origin' }).then(function(res){
      if (res.status === 401){ location.href = '/login'; throw new Error('unauthorized') }
      if (!res.ok) throw new Error('request failed: ' + res.status)
      return res.json()
    })
  }
  function el(tag, attrs, html){
    var node = document.createElement(tag)
    for (var k in attrs) node.setAttribute(k, attrs[k])
    if (html) node.innerHTML = html
    return node
  }
  fetchJSON('/api/auth/me').then(function(me){
    window.__DSH_AUTH__ = me
    var perms = me && me.permissions ? me.permissions : []
    var pages = {}
    for (var i = 0; i < perms.length; i++) if (perms[i].indexOf('page:') === 0) pages[perms[i].slice(5)] = true
    // Page-control hook: hide elements that declare a page permission the
    // current user lacks. The server still enforces access on every route.
    var targets = document.querySelectorAll('[data-dsh-page]')
    for (var j = 0; j < targets.length; j++) if (!pages[targets[j].getAttribute('data-dsh-page')]) targets[j].style.display = 'none'
    var name = me && me.username ? me.username : ''
    var roleLabel = me && me.role && me.role.label ? me.role.label : ''
    var isAdmin = !!pages['admin']
    var root = el('div', { id: 'dsh-auth-chip' }, '')
    root.style.cssText = 'position:fixed;right:14px;bottom:14px;z-index:2147483000;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;user-select:none'
    var trigger = el('button', { id: 'dsh-auth-trigger', type: 'button' }, '')
    trigger.style.cssText = 'display:flex;align-items:center;gap:6px;background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:999px;padding:6px 12px;cursor:pointer;font:inherit'
    trigger.textContent = (name ? name : 'user') + (roleLabel ? ' · ' + roleLabel : '') + ' ▾'
    var menu = el('div', { id: 'dsh-auth-menu' }, '')
    menu.style.cssText = 'position:absolute;right:0;bottom:calc(100% + 6px);min-width:160px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:4px;display:none;box-shadow:0 8px 24px rgba(1,4,9,.6)'
    var items = []
    if (isAdmin) items.push(['管理控制台', function(){ location.href = '/admin' }])
    items.push(['修改密码', function(){ location.href = '/admin#password' }])
    items.push(['退出登录', function(){ fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(function(){ location.href = '/login' }).catch(function(){ location.href = '/login' }) }])
    for (var k = 0; k < items.length; k++){
      (function(label, action){
        var item = el('button', { type: 'button' }, '')
        item.textContent = label
        item.style.cssText = 'display:block;width:100%;text-align:left;background:none;border:none;color:#c9d1d9;padding:7px 10px;border-radius:6px;cursor:pointer;font:inherit'
        item.onmouseenter = function(){ item.style.background = '#21262d' }
        item.onmouseleave = function(){ item.style.background = 'none' }
        item.onclick = action
        menu.appendChild(item)
      })(items[k][0], items[k][1])
    }
    trigger.onclick = function(){ menu.style.display = menu.style.display === 'block' ? 'none' : 'block' }
    root.appendChild(trigger)
    root.appendChild(menu)
    document.addEventListener('click', function(e){ if (e.target !== trigger && !menu.contains(e.target)) menu.style.display = 'none' })
    document.body.appendChild(root)
  }).catch(function(){})
})()`
