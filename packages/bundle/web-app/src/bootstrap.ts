/**
 * Script injected into the served SPA `index.html` through the webserver
 * index tap. It replaces the sidebar Settings trigger footprint with the
 * signed-in user as the bottom-left account trigger; clicking that trigger
 * opens a menu with user permissions, password change, settings, and logout.
 * The script styles itself with the app's own `--dsw-*` tokens, so it follows
 * the appearance setting exactly. It also redirects an expired session to
 * `/login`, exposes the session as `window.__DSH_AUTH__`, and hides
 * `[data-dsh-page]` elements whose page permission the current user lacks
 * (the page-control hook; the server enforces access regardless).
 *
 * The body is a plain <script>; it must not contain the literal sequence
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
          try { location.href = '/login' + location.search } catch (e) { /* navigation in progress */ }
        }
        return res
      })
    }
  }
  function fetchJSON(url){
    return fetch(url, { credentials: 'same-origin' }).then(function(res){
      if (res.status === 401){ location.href = '/login' + location.search; throw new Error('unauthorized') }
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
  var style = el('style', { id: 'dsh-auth-style' }, '')
  style.textContent = ''
    + '#dsh-auth-chip{position:fixed;z-index:900;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;user-select:none}'
    + '#dsh-auth-trigger{display:flex;align-items:center;gap:6px;width:100%;height:100%;background:var(--dsw-alias-bg-layer-1,#ffffff);border:1px solid var(--dsw-alias-border-l3,rgba(0,0,0,0.1));color:var(--dsw-static-neutral-bluish-1000,#0f1115);border-radius:12px;padding:0 12px;cursor:pointer;font:inherit;box-shadow:0 1px 3px rgba(0,0,0,0.1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
    + '#dsh-auth-trigger:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(0,0,0,0.06))}'
    + '#dsh-auth-trigger[data-wide="false"]{justify-content:center;padding:0;border-radius:50%;text-align:center}'
    + 'body[data-ds-dark-theme] #dsh-auth-trigger{color:var(--dsw-static-neutral-bluish-50,#f9fafb);box-shadow:0 1px 3px rgba(0,0,0,0.5)}'
    + '#dsh-auth-menu{position:fixed;z-index:1001;min-width:170px;box-sizing:border-box;background:var(--dsw-alias-bg-layer-2,#ffffff);border:1px solid var(--dsw-alias-border-l3,rgba(0,0,0,0.12));border-radius:8px;padding:4px;display:none;box-shadow:0 8px 24px rgba(0,0,0,0.18)}'
    + 'body[data-ds-dark-theme] #dsh-auth-menu{box-shadow:0 8px 24px rgba(0,0,0,0.5)}'
    + '#dsh-auth-menu button{display:block;width:100%;text-align:left;background:none;border:none;color:var(--dsw-static-neutral-bluish-1000,#0f1115);padding:7px 10px;border-radius:6px;cursor:pointer;font:inherit}'
    + 'body[data-ds-dark-theme] #dsh-auth-menu button{color:var(--dsw-static-neutral-bluish-50,#f9fafb)}'
    + '#dsh-auth-menu button:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(0,0,0,0.06))}'
    + '#dsh-auth-menu .dsh-auth-user{display:block;padding:7px 10px;margin-bottom:2px;border-bottom:1px solid var(--dsw-alias-border-l3,rgba(0,0,0,0.08));color:var(--dsw-static-neutral-bluish-1000,#0f1115);font-weight:600;white-space:nowrap}'
    + 'body[data-ds-dark-theme] #dsh-auth-menu .dsh-auth-user{color:var(--dsw-static-neutral-bluish-50,#f9fafb)}'
  document.head.appendChild(style)

  var UI = {
    root: null,
    triggerButton: null,
    menu: null,
    anchor: null,
    me: null,
    pages: {},
    open: false
  }

  function settingsTrigger(){
    return document.querySelector('[data-dsh-auth-settings-trigger]')
  }

  function accountName(user){
    return (user && user.displayName) ? user.displayName : (user && user.username ? user.username : 'user')
  }

  function accountText(user, wide){
    if (!wide) return accountName(user).slice(0, 1).toUpperCase() || 'U'
    var name = accountName(user)
    var role = user && user.role && user.role.label ? user.role.label : ''
    return role ? name + ' / ' + role : name
  }

  function sidebarColumnRect(){
    var col = document.querySelector('[data-sidebar-col]')
    if (col) return col.getBoundingClientRect()
    var trigger = settingsTrigger()
    return trigger ? trigger.getBoundingClientRect() : null
  }

  function setMenuOpen(open){
    UI.open = open
    if (UI.menu === null || UI.triggerButton === null) return
    UI.menu.style.display = open ? 'block' : 'none'
    UI.triggerButton.setAttribute('aria-expanded', open ? 'true' : 'false')
    if (open) positionUI()
  }

  function closeMenu(){
    setMenuOpen(false)
  }

  function positionMenu(){
    var trigger = settingsTrigger()
    if (UI.menu === null || trigger === null || !UI.open) return
    var rect = trigger.getBoundingClientRect()
    var col = sidebarColumnRect()
    var width = col && col.width > 0 ? col.width : (UI.menu.offsetWidth || 170)
    var left = col ? col.left : Math.max(8, Math.min(rect.left + rect.width - width, window.innerWidth - width - 8))
    UI.menu.style.width = width + 'px'
    UI.menu.style.left = left + 'px'
    UI.menu.style.top = 'auto'
    UI.menu.style.bottom = Math.max(8, window.innerHeight - rect.top + 6) + 'px'
  }

  function refreshTrigger(){
    var trigger = settingsTrigger()
    if (trigger === null || UI.triggerButton === null) return
    var wide = trigger.getAttribute('data-dsh-settings-wide') === 'true'
    UI.triggerButton.setAttribute('data-wide', wide ? 'true' : 'false')
    UI.triggerButton.textContent = accountText(UI.me, wide)
    var role = UI.me && UI.me.role && UI.me.role.label ? UI.me.role.label : ''
    UI.triggerButton.setAttribute('aria-label', accountName(UI.me) + (role ? ' / ' + role : '') + ': open user menu')
    UI.triggerButton.setAttribute('aria-expanded', UI.open ? 'true' : 'false')
  }

  function refreshMenu(){
    if (UI.menu === null) return
    UI.menu.textContent = ''
    var userRow = el('div', { class: 'dsh-auth-user' }, '')
    var role = UI.me && UI.me.role && UI.me.role.label ? UI.me.role.label : ''
    userRow.textContent = accountName(UI.me) + (role ? ' / ' + role : '')
    UI.menu.appendChild(userRow)
    var items = []
    if (UI.pages['settings']) items.push(['设置', function(){ closeMenu(); var trigger = settingsTrigger(); if (trigger) trigger.click() }])
    if (UI.pages['admin']) items.push(['用户权限', function(){ location.href = '/admin' }])
    items.push(['修改密码', function(){ location.href = '/admin#password' }])
    items.push(['退出登录', function(){
      fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
        .then(function(){ location.href = '/login' + location.search })
        .catch(function(){ location.href = '/login' + location.search })
    }])
    for (var i = 0; i < items.length; i++){
      (function(label, action){
        var item = el('button', { type: 'button', role: 'menuitem' }, '')
        item.textContent = label
        item.onclick = action
        UI.menu.appendChild(item)
      })(items[i][0], items[i][1])
    }
  }

  function positionUI(){
    var trigger = settingsTrigger()
    if (trigger === null || UI.root === null) return
    var rect = trigger.getBoundingClientRect()
    if (!rect.width || !rect.height) return
    UI.root.style.display = 'block'
    UI.root.style.left = rect.left + 'px'
    UI.root.style.top = rect.top + 'px'
    UI.root.style.width = rect.width + 'px'
    UI.root.style.height = rect.height + 'px'
    var button = UI.root.querySelector('#dsh-auth-trigger')
    if (button) button.style.borderRadius = trigger.getAttribute('data-dsh-settings-wide') === 'true' ? '12px' : '50%'
    positionMenu()
    refreshTrigger()
    applyThemeColors()
  }

  // The chip text uses static neutral tokens that do not invert with the
  // theme, so re-apply the theme's text color inline on every mount and on
  // every body palette change. This guarantees the user chip follows the
  // current skin even if a global stylesheet wins the CSS cascade.
  function applyThemeColors(){
    if (document.body === null || UI.triggerButton === null) return
    var dark = document.body.hasAttribute('data-ds-dark-theme')
    var text = dark
      ? 'var(--dsw-static-neutral-bluish-50,#f9fafb)'
      : 'var(--dsw-static-neutral-bluish-1000,#0f1115)'
    UI.triggerButton.style.color = text
    if (UI.menu !== null){
      var nodes = UI.menu.querySelectorAll('button, .dsh-auth-user')
      for (var i = 0; i < nodes.length; i++) nodes[i].style.color = text
    }
  }

  var positionScheduled = false
  function schedulePosition(){
    if (positionScheduled) return
    positionScheduled = true
    requestAnimationFrame(function(){ positionScheduled = false; positionUI() })
  }

  function mountAccountUI(){
    var trigger = settingsTrigger()
    if (!document.body || trigger === null) return
    if (UI.root !== null && UI.anchor === trigger){
      positionUI()
      return
    }
    if (UI.root !== null) UI.root.remove()
    if (UI.menu !== null) UI.menu.remove()
    UI.anchor = trigger
    UI.open = false
    trigger.style.opacity = '0'
    trigger.style.pointerEvents = 'none'
    var root = el('div', { id: 'dsh-auth-chip' }, '')
    var button = el('button', { id: 'dsh-auth-trigger', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, '')
    var menu = el('div', { id: 'dsh-auth-menu', role: 'menu' }, '')
    menu.style.display = 'none'
    root.appendChild(button)
    document.body.appendChild(root)
    document.body.appendChild(menu)
    UI.root = root
    UI.triggerButton = button
    UI.menu = menu
    button.onclick = function(){ setMenuOpen(!UI.open) }
    var closeTimer = null
    function cancelClose(){ clearTimeout(closeTimer); closeTimer = null }
    function scheduleClose(){ cancelClose(); closeTimer = setTimeout(closeMenu, 250) }
    button.addEventListener('mouseenter', function(){ cancelClose(); setMenuOpen(true) })
    button.addEventListener('mouseleave', scheduleClose)
    menu.addEventListener('mouseenter', cancelClose)
    menu.addEventListener('mouseleave', scheduleClose)
    document.addEventListener('click', function(e){
      if (e.target !== button && !menu.contains(e.target)) closeMenu()
    })
    refreshMenu()
    positionUI()
    window.addEventListener('resize', schedulePosition)
    if (window.MutationObserver){
      new MutationObserver(function(){
      schedulePosition()
      applyThemeColors()
      if (settingsTrigger() !== UI.anchor) mountAccountUI()
      })
        .observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-dsh-settings-wide', 'data-ds-dark-theme', 'class', 'style'] })
    }
  }

  try { window.__DSH_AUTH__ = null } catch (e) { /* signal simply stays absent */ }
  fetchJSON('/api/auth/me').then(function(me){
    window.__DSH_AUTH__ = me
    try { window.dispatchEvent(new CustomEvent('dsh-auth', { detail: me })) } catch (e) { /* consumers read __DSH_AUTH__ on their own schedule */ }
    var perms = me && me.permissions ? me.permissions : []
    var pages = {}
    for (var i = 0; i < perms.length; i++) if (perms[i].indexOf('page:') === 0) pages[perms[i].slice(5)] = true
    // Page-control hook: hide elements that declare a page permission the
    // current user lacks. The server still enforces access on every route.
    var targets = document.querySelectorAll('[data-dsh-page]')
    for (var j = 0; j < targets.length; j++) if (!pages[targets[j].getAttribute('data-dsh-page')]) targets[j].style.display = 'none'
    UI.me = me
    UI.pages = pages
    function tryMount(){
      if (!document.body){ setTimeout(tryMount, 50); return }
      if (settingsTrigger() === null){ setTimeout(tryMount, 250); return }
      mountAccountUI()
    }
    tryMount()
  }).catch(function(){})
})()`
