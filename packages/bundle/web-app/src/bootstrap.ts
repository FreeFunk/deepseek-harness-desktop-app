/**
 * Script injected into the served SPA `index.html` through the webserver
 * index tap. It surfaces the signed-in user as a compact pill at the bottom
 * left of the content column — anchored to the sidebar's right edge, the same
 * level as the sidebar's Settings trigger (the deepseek.com avatar position)
 * — with a menu for the admin console, password change, and logout. The pill
 * styles itself with the app's own `--dsw-*` tokens, so it follows the
 * appearance setting (light/dark/system) exactly. The script also redirects
 * an expired session to `/login`, exposes the session as
 * `window.__DSH_AUTH__`, and hides `[data-dsh-page]` elements whose page
 * permission the current user lacks (the page-control hook; the server
 * enforces access regardless).
 *
 * The body is a plain <script> — it must not contain the literal sequence
 * `</script>`, so none is emitted except the real closing tag at the end.
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
  // Themed with the app's design tokens so the pill follows the appearance
  // setting; the dark overrides key off body[data-ds-dark-theme], which the
  // app's own theme bootstrap already toggles.
  var style = el('style', { id: 'dsh-auth-style' }, '')
  style.textContent = ''
    + '#dsh-auth-chip{position:fixed;left:14px;bottom:14px;z-index:2147483000;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;user-select:none}'
    + '#dsh-auth-trigger{display:flex;align-items:center;gap:6px;background:var(--dsw-alias-bg-layer-1);border:1px solid var(--dsw-alias-border-l3);color:var(--dsw-static-neutral-bluish-1000);border-radius:999px;padding:6px 12px;cursor:pointer;font:inherit;box-shadow:0 1px 3px rgba(0,0,0,0.1)}'
    + '#dsh-auth-trigger:hover{background:var(--dsw-alias-interactive-bg-hover)}'
    + 'body[data-ds-dark-theme] #dsh-auth-trigger{color:var(--dsw-static-neutral-bluish-50);box-shadow:0 1px 3px rgba(0,0,0,0.5)}'
    + '#dsh-auth-menu{position:absolute;left:0;bottom:calc(100% + 6px);min-width:170px;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l3);border-radius:8px;padding:4px;display:none;box-shadow:0 8px 24px rgba(0,0,0,0.18)}'
    + 'body[data-ds-dark-theme] #dsh-auth-menu{box-shadow:0 8px 24px rgba(0,0,0,0.5)}'
    + '#dsh-auth-menu button{display:block;width:100%;text-align:left;background:none;border:none;color:var(--dsw-static-neutral-bluish-1000);padding:7px 10px;border-radius:6px;cursor:pointer;font:inherit}'
    + 'body[data-ds-dark-theme] #dsh-auth-menu button{color:var(--dsw-static-neutral-bluish-50)}'
    + '#dsh-auth-menu button:hover{background:var(--dsw-alias-interactive-bg-hover)}'
  document.head.appendChild(style)
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
    var trigger = el('button', { id: 'dsh-auth-trigger', type: 'button' }, '')
    trigger.textContent = (name ? name : 'user') + (roleLabel ? ' · ' + roleLabel : '') + ' ▾'
    var menu = el('div', { id: 'dsh-auth-menu' }, '')
    var items = []
    if (isAdmin) items.push(['管理控制台', function(){ location.href = '/admin' }])
    items.push(['修改密码', function(){ location.href = '/admin#password' }])
    items.push(['退出登录', function(){ fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(function(){ location.href = '/login' }).catch(function(){ location.href = '/login' }) }])
    for (var k = 0; k < items.length; k++){
      (function(label, action){
        var item = el('button', { type: 'button' }, '')
        item.textContent = label
        item.onclick = action
        menu.appendChild(item)
      })(items[k][0], items[k][1])
    }
    trigger.onclick = function(){ menu.style.display = menu.style.display === 'block' ? 'none' : 'block' }
    root.appendChild(trigger)
    root.appendChild(menu)
    document.addEventListener('click', function(e){ if (e.target !== trigger && !menu.contains(e.target)) menu.style.display = 'none' })
    // Anchor the pill to the sidebar's right edge (its drag handle is a stable
    // data-side=sidebar element), so it sits in the content column's bottom
    // left at the same level as the Settings trigger; re-anchor on any layout
    // change (sidebar drag/collapse) via a rAF-throttled MutationObserver.
    var scheduled = false
    function positionChip(){
      var handle = document.querySelector('[data-side="sidebar"]')
      if (handle){
        var rect = handle.getBoundingClientRect()
        root.style.left = Math.max(8, Math.round(rect.left + rect.width / 2 + 14)) + 'px'
      } else {
        root.style.left = '14px'
      }
    }
    function schedulePosition(){
      if (scheduled) return
      scheduled = true
      requestAnimationFrame(function(){ scheduled = false; positionChip() })
    }
    window.addEventListener('resize', schedulePosition)
    if (document.body && window.MutationObserver){
      new MutationObserver(schedulePosition).observe(document.body, { attributes: true, attributeFilter: ['style', 'class'], subtree: true })
    }
    positionChip()
    document.body.appendChild(root)
  }).catch(function(){})
})()`
