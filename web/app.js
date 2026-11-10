const $ = s => document.querySelector(s)
const $$ = s => [...document.querySelectorAll(s)]
const N = 120, KEEP = 600, SHOW = 150, PLAN_ALERT = 80
const fmt = n => (n ?? 0).toLocaleString()
const proxied = location.pathname.includes('/_limitplane')
const clock = t => new Date(t).toLocaleTimeString([], { hour12: false })
const labelCls = { human: 'ok', bot: 'bad', retry_bug: 'warn' }
const reasonCls = r => (r === 'banned' || r === 'error' ? 'bad' : 'warn')

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) k in e ? (e[k] = v) : e.setAttribute(k, v)
  e.append(...kids.filter(k => k != null))
  return e
}

// IPs and CIDRs, parsed to BigInts: enough to validate a ban and to match clients against a range.
// The gateway bans by client IP, so a ban target is an IP or a CIDR; the server canonicalises it.
function parseIP(s) {
  const v4 = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(s)
  if (v4) {
    const p = v4.slice(1).map(Number)
    return p.every(x => x < 256) ? { v: 4, n: p.reduce((a, x) => a * 256n + BigInt(x), 0n), len: 32 } : null
  }
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return null
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s) // ::ffff:192.0.2.1
  if (m) {
    const t = parseIP(m[2])
    if (t?.v !== 4) return null
    s = m[1] + (t.n >> 16n).toString(16) + ':' + (t.n & 0xffffn).toString(16)
  }
  const halves = s.split('::'), part = x => (x ? x.split(':') : [])
  if (halves.length > 2) return null
  const [a, b] = halves.map(part), fill = b ? 8 - a.length - b.length : 0
  if (b && fill < 1) return null
  const groups = b ? [...a, ...Array(fill).fill('0'), ...b] : a
  if (groups.length !== 8 || !groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return null
  const n = groups.reduce((x, g) => x * 65536n + BigInt('0x' + g), 0n)
  return n >> 32n === 0xffffn ? { v: 4, n: n & 0xffffffffn, len: 32 } : { v: 6, n, len: 128 } // IPv4-mapped counts as IPv4
}
const v4Text = n => [24n, 16n, 8n, 0n].map(k => (n >> k) & 255n).join('.')
const MIN_BITS = { 4: 8, 6: 16 } // a wider range is almost always a typo (10.0.0.0/2 for /24)
// parseTarget: { ip, bits, net, cidr, text } or { error }
function parseTarget(raw) {
  const [ip, bits, extra] = raw.trim().split('/')
  const a = ip && parseIP(ip)
  if (extra != null || !a) return { error: 'Not an IP or CIDR. Bans match the client IP, e.g. 203.0.113.7 or 10.0.0.0/24.' }
  if (bits == null) return { ...a, bits: a.len, cidr: false, text: a.v === 4 ? v4Text(a.n) : ip.toLowerCase() }
  if (!/^\d{1,3}$/.test(bits) || +bits > a.len) return { error: `The prefix length must be 0 to ${a.len} for IPv${a.v}.` }
  const b = +bits, host = BigInt(a.len - b), net = (a.n >> host) << host
  if (b < MIN_BITS[a.v]) return { error: `/${b} is wider than /${MIN_BITS[a.v]}. Ban a narrower range.` }
  if (b === a.len) return { ...a, bits: b, cidr: false, text: a.v === 4 ? v4Text(a.n) : ip.toLowerCase() }
  // IPv6 text is left for the server to canonicalise; IPv4 is masked here so the label matches the list
  return { v: a.v, n: net, len: a.len, bits: b, cidr: true, masked: net !== a.n, text: a.v === 4 ? `${v4Text(net)}/${b}` : `${ip.toLowerCase()}/${b}` }
}
const rangeText = t => (t.v === 4 ? `${fmt(2 ** (32 - t.bits))} addresses` : `/${t.bits} range`)
const inRange = (t, ip) => {
  const a = parseIP(ip)
  if (!a || a.v !== t.v) return false
  const host = BigInt(t.len - t.bits)
  return a.n >> host === t.n >> host
}
// path segments encoded one by one, so a CIDR's slash stays a separator (api/bans/10.0.0.0/24):
// the server routes it with {client...}, and proxies that reject %2F never see one
const banPath = client => 'bans/' + client.split('/').map(encodeURIComponent).join('/')

const store = k => ({
  get() { try { return sessionStorage.getItem(k) } catch { return null } },
  set(v) { try { v ? sessionStorage.setItem(k, v) : sessionStorage.removeItem(k) } catch {} },
})
const session = store('lp-token'), orgStore = store('lp-org')
let token = session.get()

// who is signed in: {user, email, org, orgName, role}; role is superadmin, owner, admin or viewer
let me = null
const rank = { viewer: 1, admin: 2, owner: 3 }
const isSuper = () => me?.role === 'superadmin'
const can = role => isSuper() || (rank[me?.role] || 0) >= rank[role]
// the org in view: the superadmin's pick from the switcher ('' = all), else the member's own
let scopeOrg = orgStore.get() || ''
const viewOrg = () => (isSuper() ? scopeOrg : me?.org || '')
// scoped reads carry the superadmin's pick; members' are scoped by the server regardless
const orgQ = path => (isSuper() && scopeOrg ? path + (path.includes('?') ? '&' : '?') + 'org=' + encodeURIComponent(scopeOrg) : path)
const enc = encodeURIComponent

async function api(path, opts = {}) {
  const r = await fetch('api/' + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) },
  })
  if (r.status === 401 && path !== 'login' && path !== 'signup') { logout(); throw new Error('session expired') }
  const text = await r.text()
  let body = text
  try { body = JSON.parse(text) } catch {}
  if (!r.ok) throw new Error(body?.message || body?.error || text || r.statusText)
  return body
}

function toast(text, kind = '') {
  const box = $('#toasts')
  const t = h('div', { className: 'toast ' + kind }, text)
  box.append(t)
  while (box.children.length > 4) box.firstChild.remove()
  setTimeout(() => t.remove(), kind === 'bad' ? 7000 : 3500)
}

// theme
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches }
function toggleTheme() {
  const root = document.documentElement
  root.dataset.theme = isDark() ? 'light' : 'dark'
  try { localStorage.setItem('lp-theme', root.dataset.theme) } catch {}
  draw()
}
$('#theme').onclick = toggleTheme
if (!/Mac|iPhone|iPad/.test(navigator.platform)) $$('.mod').forEach(e => { e.textContent = 'Ctrl ' })
$('#cmdk').title = `Command palette (${/Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl+'}K)`

// auth: email and password, the admin key, or (when the server allows it) a new org
let loginMode = 'user', signupOn = false
function setMode(m) {
  loginMode = m
  const key = m === 'key', up = m === 'signup'
  $('#fUser').hidden = key; $('#fKey').hidden = !key
  $('#lOrgL').hidden = !up
  $('#password').autocomplete = up ? 'new-password' : 'current-password'
  $('#loginTitle').replaceChildren(up ? 'Create an org on ' : 'Sign in to ', h('em', {}, 'LimitPlane'))
  $('#loginSub').textContent = key ? 'Use the admin key the gateway was started with.' : up ? 'You become its owner and can invite the rest of your team.' : 'Use your email and password.'
  $('#userGo').textContent = up ? 'Create org' : 'Sign in'
  $('#modeKey').textContent = key ? 'Use email and password' : 'Use the admin key'
  $('#modeSignup').hidden = !signupOn || key
  $('#modeSignup').textContent = up ? 'I have an account' : 'Create an org'
  $('#loginMsg').textContent = ''
  ;(key ? $('#key') : up ? $('#lOrg') : $('#email')).focus()
}
$('#modeKey').onclick = () => setMode(loginMode === 'key' ? 'user' : 'key')
$('#modeSignup').onclick = () => setMode(loginMode === 'signup' ? 'user' : 'signup')
$('#loginForm').onsubmit = async e => {
  e.preventDefault()
  const msg = $('#loginMsg')
  msg.textContent = ''
  let path = 'login', body
  if (loginMode === 'key') body = { key: $('#key').value }
  else {
    body = { email: $('#email').value.trim(), password: $('#password').value }
    if (loginMode === 'signup') { path = 'signup'; body.org = $('#lOrg').value.trim() }
    const miss = loginMode === 'signup' && !body.org ? 'lOrg' : !body.email ? 'email' : !body.password ? 'password' : ''
    if (miss) { msg.textContent = 'Fill in every field.'; return $('#' + miss).focus() }
  }
  try {
    signedIn(await api(path, { method: 'POST', body: JSON.stringify(body) }))
    $('#password').value = ''; $('#key').value = ''
    start()
  } catch (err) {
    msg.textContent = err.message || 'Sign in failed.'
  }
}
function signedIn(s) {
  token = s.token
  session.set(token)
  me = { user: s.user, email: s.email, org: s.org, orgName: s.orgName, role: s.role }
}
$('#logout').onclick = () => logout()
$('#keyShow').onclick = () => {
  const k = $('#key'), on = k.type === 'password'
  k.type = on ? 'text' : 'password'
  $('#keyShow').setAttribute('aria-pressed', on)
}

let timers = [], es
function logout() {
  token = null
  me = null
  session.set(null)
  scopeOrg = ''; orgStore.set(null); orgInfo = null; members = null; otenants = []; orgs = []
  for (const k in loaded) loaded[k] = false
  timers.forEach(clearInterval)
  timers = []
  es?.close()
  es = null
  buf = []; els.clear(); $('#feed').replaceChildren()
  show(false)
}

function show(authed) {
  $('#login').hidden = authed
  $('#main').hidden = !authed
  for (const id of ['tabs', 'logout', 'helpBtn', 'cmdk', 'whoami']) $('#' + id).hidden = !authed
  $('[data-tab=try]').hidden = proxied
  if (authed) return roleUI()
  $('#key').type = 'password'; $('#keyShow').setAttribute('aria-pressed', false)
  setMode(loginMode)
}

// role-aware chrome: the server enforces all of it, this only hides what would be refused
function roleUI() {
  const sup = isSuper()
  $('[data-tab=policy]').hidden = !sup
  $('#banForm').hidden = $('#banMsg').hidden = !sup
  $('#dBan').hidden = !sup
  $('#orgPick').hidden = !sup
  const who = $('#whoami')
  who.textContent = [me.user === 'admin' ? 'admin key' : me.email, me.role, me.orgName || me.org].filter(Boolean).join(' · ')
  who.title = `Signed in as ${me.email || 'the admin key'}, ${me.role}${me.org ? ' in ' + (me.orgName || me.org) : ', every org'}`
  $('[data-tab=org]').textContent = sup ? 'Orgs' : 'Org'
}

// views
const views = $$('[data-view]').map(e => e.dataset.view)
const allowed = v => views.includes(v) && !(v === 'try' && proxied) && !(v === 'policy' && !isSuper())
const shownViews = () => views.filter(allowed)
function route(focus) {
  let v = location.hash.replace(/^#\//, '')
  if (!allowed(v)) v = 'overview'
  $$('[data-view]').forEach(e => { e.hidden = e.dataset.view !== v })
  $$('[data-tab]').forEach(a => a.dataset.tab === v ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'))
  document.title = v[0].toUpperCase() + v.slice(1) + ' · LimitPlane'
  if (v === 'org') loadOrgView()
  draw()
  const a = document.activeElement
  if (focus && (a === document.body || a.closest('nav'))) $('#h-' + v).focus({ preventScroll: true })
}
addEventListener('hashchange', () => route(true))
$('.skip').onclick = e => { e.preventDefault(); $('#main').focus() }

async function start() {
  if (!me) {
    try { me = await api('me') } catch { return logout() }
  }
  if (!isSuper()) scopeOrg = ''
  show(true)
  route()
  refresh(true)
  loadPolicy()
  loadOrgs()
  loadAudit().finally(connect)
  timers.push(setInterval(refresh, 4000), setInterval(tick, 1000))
}

// the superadmin's org switcher: every scoped read and the live stream follow it
$('#orgPick').onchange = e => switchOrg(e.target.value)
function switchOrg(id) {
  scopeOrg = id
  orgStore.set(id)
  $('#orgPick').value = id
  buf = []; els.clear(); $('#feed').replaceChildren(); members = null
  for (const k of ['tenants', 'clients', 'bans', 'otenants']) loaded[k] = false
  $('#otenants').dataset.sig = ''
  refresh(true)
  loadAudit().finally(connect)
  if (location.hash === '#/org') loadOrgView()
}

function tick() {
  advance(); draw(); updateNotice()
  $('#finding').textContent = finding()
  $$('[data-until]').forEach(e => { e.textContent = left(e.dataset.until) })
  const last = series[series.length - 1]
  if (last) $('#chart').setAttribute('aria-label', `Allowed and blocked requests per second, last 120 seconds. Now ${last.allowed} allowed and ${last.blocked} blocked. Use the arrow keys to read each second.`)
}

// stats
let series = [], totals = { total: 0, allowed: 0, blocked: 0 }
let tenants = [], clients = [], bans = [], banned = new Set(), banNets = []
let cluster = { backend: '', kube: false, leader: false }
// banned: exact match, or inside a CIDR ban
const isBanned = ip => banned.has(ip) || banNets.some(t => inRange(t, ip))
let policyCfg = null, degraded = false, degradedUntil = 0, lastOk = 0
const loaded = {}

function advance(now = Math.floor(Date.now() / 1000)) {
  const last = series.length ? series[series.length - 1].t : now - N
  for (let t = Math.max(last + 1, now - N + 1); t <= now; t++) series.push({ t, allowed: 0, blocked: 0 })
  if (series.length > N) series = series.slice(-N)
}

function failed(id, what, reason) {
  if (loaded[id]) return
  const row = h('div', { className: 'state-row bad' }, `Couldn't load ${what} (${reason.message}). `, h('button', { className: 'link', type: 'button', onclick: () => refresh() }, 'Retry'))
  $('#' + id).replaceChildren(id === 'clients' ? h('div', { className: 'rows' }, row) : row)
}

async function refresh(seed) {
  const [s, c, b, t] = await Promise.allSettled([api(orgQ('stats')), api(orgQ('clients')), api(orgQ('bans')), api(orgQ('tenants'))])
  if (t.status === 'fulfilled') { otenants = t.value || []; loaded.otenants = true; renderOrgTenants() }
  if (s.status === 'fulfilled') {
    const v = s.value
    orgInfo = v.org || null
    renderBudget()
    totals = { total: v.total, allowed: v.allowed, blocked: v.blocked }
    degraded = v.degraded
    cluster = { backend: v.backend, kube: !!v.kube, leader: !!v.leader }
    if (seed === true) { series = (v.series || []).map(p => ({ ...p })); advance(); draw() }
    tenants = v.tenants || []; loaded.tenants = true
    renderTenants(); updateNotice()
  } else failed('tenants', 'monthly quotas', s.reason)
  if (c.status === 'fulfilled') { clients = c.value || []; loaded.clients = true } else failed('clients', 'clients', c.reason)
  if (b.status === 'fulfilled') {
    bans = b.value || []; loaded.bans = true
    banned = new Set(bans.map(x => x.client))
    banNets = bans.map(x => parseTarget(x.client)).filter(t => t.cidr)
  } else failed('bans', 'bans', b.reason)
  if (loaded.clients) renderClients()
  if (loaded.bans) renderBans()
  renderTotals()
  const ok = [s, c, b].every(r => r.status === 'fulfilled')
  if (ok) lastOk = Date.now()
  const st = $('#stamp')
  st.className = 'stamp' + (ok ? '' : ' bad')
  st.textContent = ok ? 'Updated ' + clock(lastOk) : lastOk ? "Couldn't refresh · last " + clock(lastOk) : "Couldn't load data"
  $('#app').removeAttribute('data-loading')
}
$('#refresh').onclick = () => refresh()

function renderTotals() {
  const { total, allowed, blocked } = totals
  $('#kTotal').textContent = fmt(total)
  $('#kAllowed').textContent = fmt(allowed)
  $('#kBlocked').textContent = fmt(blocked)
  $('#kRate').replaceChildren((total ? 100 * blocked / total : 0).toFixed(1), h('small', {}, '%'))
  const done = series.slice(-6, -1)
  $('#kNow').replaceChildren((done.reduce((a, p) => a + p.allowed + p.blocked, 0) / Math.max(1, done.length)).toFixed(1), h('small', {}, '/s'))
  $('#kBans').textContent = fmt(bans.length)
  $('#bansPill').textContent = `${bans.length} ${bans.length === 1 ? 'ban' : 'bans'} active`
  $('#bansPill').className = 'pill' + (bans.length ? ' warn' : '')
}

// status pills: backend, degraded while the fallback answers, and the replica's role in --kube mode
function renderStatus() {
  const on = degraded || Date.now() < degradedUntil
  const be = $('#backend')
  if (cluster.backend) be.textContent = cluster.backend
  be.title = cluster.backend === 'redis' ? 'Limits and bans are shared through Redis' : cluster.backend === 'memory' ? 'Limits and bans live in this process only' : be.title
  $('#degraded').hidden = !on
  const k = $('#kube')
  k.hidden = !cluster.kube
  k.textContent = 'kube · ' + (cluster.leader ? 'leader' : 'follower')
  k.className = 'pill' + (cluster.leader ? ' ok' : '')
  k.title = cluster.leader ? 'Operator mode. This replica holds the Lease and writes status and Events.' : 'Operator mode. Another replica holds the Lease; this one serves the same policy.'
}

function updateNotice() {
  renderStatus()
  const on = degraded || Date.now() < degradedUntil
  const n = $('#notice')
  if (n.hidden === !on) return
  n.hidden = !on
  n.replaceChildren(h('b', {}, 'Shared backend unreachable. '), 'Each replica limits from its own memory on its share of the budget until Redis recovers. Monthly counts restart locally, so they can drift.')
}

const rateText = tier => {
  const r = policyCfg?.tiers?.[tier]?.rate
  return r ? `${r.limit}/${r.period === '1s' ? 's' : r.period} · burst ${r.burst}` : ''
}
const col = (cls, ...kids) => h('span', { className: cls }, ...kids)
const head = (names, nums = []) => h('div', { className: 'hd' }, ...names.map((n, i) => col(nums.includes(i) ? 'num' : '', n)))
function list(el, hd, rows, empty) {
  el.replaceChildren(...(hd ? [hd] : []), ...(rows.length ? rows : [h('div', { className: 'state-row' }, empty)]))
}

function renderTenants() {
  if (!loaded.tenants) return
  const pct = t => (t.monthlyLimit ? 100 * t.monthlyUsed / t.monthlyLimit : -1)
  const all = isSuper() && !scopeOrg
  const rows = [...tenants].sort((a, b) => pct(b) - pct(a) || a.tenant.localeCompare(b.tenant)).map(t => {
    const p = pct(t)
    return h('div', { className: 'r' },
      h('div', {}, col('mono', t.tenant), col('sub2', [all && t.org && 'org ' + t.org, t.tier, rateText(t.tier)].filter(Boolean).join(' · '))),
      p < 0 ? col('sub2', 'No monthly cap') : gauge(t.monthlyUsed, t.monthlyLimit, t.tenant + ' monthly quota', 'quota used up'),
      col('num mono', fmt(t.allowed)), col('num mono', fmt(t.blocked)),
      col('meta2 mono', `${fmt(t.allowed)} allowed · ${fmt(t.blocked)} blocked`))
  })
  // the org's shared budget heads the list: it caps every row below it together
  if (orgInfo) rows.unshift(h('div', { className: 'r orgrow' },
    h('div', {}, col('mono', orgInfo.name || orgInfo.id), col('sub2', 'org budget, shared')),
    orgInfo.budget ? gauge(orgInfo.used, orgInfo.budget, orgInfo.id + ' shared monthly budget', 'budget used up') : col('sub2', `No budget · ${fmt(orgInfo.used)} used`),
    col('num mono', fmt(totals.allowed)), col('num mono', fmt(totals.blocked)),
    col('meta2 mono', `${fmt(totals.allowed)} allowed · ${fmt(totals.blocked)} blocked`)))
  list($('#tenants'), head(['Tenant', 'Monthly quota', 'Allowed', 'Blocked'], [2, 3]), rows, 'No tenants yet.')
  const now = new Date()
  $('#resets').textContent = 'Resets in ' + Math.ceil((Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1) - now) / 864e5) + ' d (UTC)'
}

// gauge: used of limit, with the 80% alert line and warn/bad past it (tenant quotas and org budgets)
function gauge(used, limit, label, full) {
  const p = 100 * used / limit, state = p >= 100 ? 'bad' : p >= PLAN_ALERT ? 'warn' : ''
  const pc = p < 10 ? p.toFixed(1) : Math.round(p)
  return h('div', {},
    h('div', { className: 'plan-l' }, h('span', {}, h('b', {}, fmt(used)), ' of ' + fmt(limit)),
      state ? h('span', { className: 'pill ' + state, title: `Alert line is ${PLAN_ALERT}% of the limit` }, state === 'bad' ? full : `${pc}% used`) : h('span', {}, pc + '%')),
    h('div', { className: 'plan ' + state, role: 'progressbar', 'aria-label': label, 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(Math.min(100, p)) }, h('i', { style: `width:${Math.min(100, p)}%` })))
}

function renderRoutes() {
  const cfg = policyCfg, anon = cfg.anonymous, burst = cfg.tiers[anon]?.rate.burst || 0
  const routes = [...cfg.routes].sort((a, b) => b.cost - a.cost || a.prefix.localeCompare(b.prefix))
  const max = Math.max(1, ...routes.map(r => r.cost))
  const row = (prefix, cost, dim) => h('div', { className: 'r' },
    col('mono ell' + (dim ? ' sub2' : ''), prefix),
    h('div', {}, col('num mono', cost), h('div', { className: 'thin' }, h('i', { style: `width:${100 * cost / max}%` }))),
    col('num mono', burst ? Math.floor(burst / cost) + '×' : '—'))
  list($('#routes'), head(['Prefix', 'Cost', 'Per burst'], [1, 2]), [...routes.map(r => row(r.prefix, r.cost)), row('anything else', 1, true)], '')
  $('#routesNote').textContent = `Longest prefix wins. Per burst is how many calls fit the ${anon} tier's burst of ${burst}, in one go.`
}

function renderTiers() {
  const cfg = policyCfg
  const rows = Object.entries(cfg.tiers).map(([name, t]) => h('div', { className: 'r' },
    col('lbl ell', name),
    h('div', {}, col('mono', `${t.rate.limit}/${t.rate.period === '1s' ? 's' : t.rate.period} · burst ${t.rate.burst}`), col('sub2', (t.monthly ? fmt(t.monthly) + ' per month' : 'No monthly cap') +
      (t.lanes ? ' · burst ' + Object.entries(t.lanes).map(([l, f]) => `${l} ×${f}`).join(', ') : '')))))
  list($('#tiers'), null, rows, 'No tiers.')
  const n = Object.keys(cfg.keys).length
  $('#tierNote').textContent = `${n} API ${n === 1 ? 'key' : 'keys'}. Requests without a known key are limited per client IP on the ${cfg.anonymous} tier.`
  $('#keys').replaceChildren(...Object.entries(cfg.keys).map(([k, t]) => h('option', { value: k, label: `${t.id} (${t.tier})` })))
  const sel = $('#tenantForm').tier, cur = sel.value
  sel.replaceChildren(...Object.keys(cfg.tiers).map(n => h('option', { value: n }, n)))
  sel.value = cur in cfg.tiers ? cur : cfg.anonymous
}

function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000))
  return isNaN(s) ? '—' : s < 60 ? s + 's ago' : Math.round(s / 60) + 'm ago'
}

const icon12 = d => {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  s.setAttribute('viewBox', '0 0 12 12'); s.setAttribute('width', 12); s.setAttribute('height', 12); s.setAttribute('aria-hidden', 'true')
  s.innerHTML = `<path d="${d}" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>`
  return s
}
const arrowIcon = () => icon12('M3.5 8.5l5-5M4.5 3.5h4v4')
const askIcon = () => icon12('M4.2 4.4a1.9 1.9 0 1 1 2.6 1.8c-.5.2-.8.6-.8 1.1v.3M6 9.6v.1')

function renderClients() {
  const cards = clients.map(c => {
    const pct = Math.round((c.blockRatio ?? 0) * 100), rps = (c.rps ?? 0).toFixed(1)
    return h('article', { className: 'ccard' },
      h('div', { className: 'ctop' }, col('cid', c.client),
        h('button', { className: 'arrow', type: 'button', title: 'Explain ' + c.client, 'aria-label': 'Explain ' + c.client, onclick: () => window.lpAI?.client(c.client) }, askIcon()),
        h('button', { className: 'arrow', type: 'button', title: 'Show decisions from ' + c.client, 'aria-label': 'Show decisions from ' + c.client, onclick: () => viewClient(c.client) }, arrowIcon())),
      h('p', { className: 'sub2' }, `${rps}/s · `, col(pct >= 50 ? 'badtxt' : '', pct + '% blocked'), h('br'), 'seen ' + ago(c.lastSeen),
        ...(c.lane ? [h('br'), h('span', { title: `Its tier has lanes: as a ${c.lane} it gets a burst of ${fmt(c.burst)}. Rate and monthly quota are unchanged.` }, `lane ${c.lane} · burst ${fmt(c.burst)}`)] : [])),
      h('div', { className: 'cfoot' }, col('pill ' + (labelCls[c.label] ?? ''), c.label || 'unknown'),
        isBanned(c.client) ? col('pill warn', 'banned') : isSuper() ? h('button', { className: 'btn small', type: 'button', 'aria-label': 'Ban ' + c.client + ' for 10 minutes', onclick: () => ban(c.client, 10, 'manual') }, 'Ban') : null))
  })
  $('#clients').replaceChildren(...(cards.length ? cards : [h('div', { className: 'rows' }, h('div', { className: 'state-row' }, 'No clients have sent traffic yet.'))]))
  $('#clCount').textContent = `${clients.length} ${clients.length === 1 ? 'client' : 'clients'}`
}

function left(until) {
  const s = Math.round((Date.parse(until) - Date.now()) / 1000)
  return s <= 0 ? 'expired' : s < 60 ? s + 's left' : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s left` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m left`
}

function renderBans() {
  const rows = bans.map(b => {
    const t = parseTarget(b.client), n = t.cidr ? clients.filter(c => inRange(t, c.client)).length : 0
    return h('div', { className: 'r' },
    h('div', {}, col('mono ell', b.client), t.cidr ? h('span', { className: 'sub2 ell', title: `${n} active ${n === 1 ? 'client' : 'clients'} in this range` }, rangeText(t) + (n ? ` · ${n} active` : '')) : null),
    h('div', {}, h('span', { className: 'mono', 'data-until': b.until }, left(b.until)), col('sub2 ell', b.reason || 'manual')),
    isSuper() ? h('button', { className: 'btn small', type: 'button', 'aria-label': 'Unban ' + b.client, onclick: () => unban(b.client) }, 'Unban') : h('span'))
  })
  list($('#bans'), head(['Client', 'Expires', '']), rows, isSuper() ? 'Nobody is banned.' : 'None of your clients is banned.')
}

async function ban(client, minutes, reason) {
  $('#banMsg').textContent = ''
  try {
    await api('bans', { method: 'POST', body: JSON.stringify({ client, minutes, reason }) })
    toast(`Banned ${client} for ${minutes} min`, 'ok')
    await refresh()
    return true
  } catch (err) {
    $('#banMsg').textContent = err.message
    toast('Ban failed: ' + err.message, 'bad')
    return false
  }
}

async function unban(client) {
  try {
    await api(banPath(client), { method: 'DELETE' })
    toast('Unbanned ' + client, 'ok')
    refresh()
  } catch (err) { toast('Unban failed: ' + err.message, 'bad') }
}

$('#banForm').onsubmit = async e => {
  e.preventDefault()
  const f = e.target, m = Number(f.minutes.value), raw = f.client.value.trim()
  const t = raw ? parseTarget(raw) : { error: 'Enter an IP or a CIDR, e.g. 203.0.113.7 or 10.0.0.0/24.' }
  const badClient = t.error, bad = badClient || (!(Number.isInteger(m) && m >= 1 && m <= 10080) ? 'Minutes must be a whole number from 1 to 10080.' : '')
  f.client.setAttribute('aria-invalid', !!badClient)
  f.minutes.setAttribute('aria-invalid', !badClient && !!bad)
  if (bad) {
    $('#banMsg').textContent = bad
    return (badClient ? f.client : f.minutes).focus()
  }
  if (await ban(t.text, m, f.reason.value.trim() || 'manual')) f.reset()
}

// live events
let backoff = 1000
function connect() {
  if (!token) return
  es?.close()
  setLive(false)
  es = new EventSource(orgQ('api/events?token=' + encodeURIComponent(token)))
  es.onopen = () => { backoff = 1000; setLive(true); refresh(true) }
  es.addEventListener('decision', e => onDecision(JSON.parse(e.data)))
  window.lpAI?.listen(es)
  es.addEventListener('ban', e => {
    const b = JSON.parse(e.data)
    toast(`Ban added: ${b.client}${b.reason ? ' (' + b.reason + ')' : ''}`, 'warn')
    refresh()
  })
  es.onerror = () => {
    es.close()
    setLive(false)
    if (!token) return
    // EventSource hides the status code, so probe once to catch an expired token.
    api(orgQ('stats')).catch(() => {})
    setTimeout(connect, backoff)
    backoff = Math.min(backoff * 2, 30000)
  }
}

function setLive(on) {
  const l = $('#live')
  l.className = 'pill ' + (on ? 'ok live' : 'warn')
  l.lastChild.textContent = on ? 'live' : 'reconnecting'
}

// decisions feed
let buf = [], seq = 0, paused = false, pauseSeq = 0, sel = 0, frame = 0
const flt = { kind: 'all', q: '' }
const els = new Map(), chipEls = new Map()

function ingest(d) {
  d._seq = ++seq
  d._ms = Date.parse(d.time) || Date.now()
  buf.push(d)
  if (buf.length > KEEP) buf.splice(0, buf.length - KEEP)
}

async function loadAudit() {
  try {
    const a = await api(orgQ('audit?limit=200'))
    a.reverse().forEach(ingest)
  } catch (err) {
    $('#feedEmpty').dataset.s = 'err'
    $('#feedEmpty').replaceChildren(`Couldn't load recent decisions (${err.message}). `, h('button', { className: 'link', type: 'button', onclick: () => loadAudit() }, 'Retry'))
  }
  renderFeed()
}

function onDecision(d) {
  totals.total++
  d.allowed ? totals.allowed++ : totals.blocked++
  advance()
  const t = Math.floor(Date.parse(d.time) / 1000)
  const b = series.find(p => p.t === t) || series[series.length - 1]
  if (b) d.allowed ? b.allowed++ : b.blocked++
  if (d.degraded) degradedUntil = Date.now() + 8000
  globe.decision(d.client || '?', d.allowed ? 'ok' : d.reason === 'burst' ? 'warn' : 'bad', d.allowed ? 'ok' : d.reason)
  ingest(d)
  frame ||= requestAnimationFrame(() => { frame = 0; renderFeed(); renderTotals() })
}

const matchQ = d => !flt.q || `${d.method} ${d.path} ${d.client} ${d.tenant} ${d.reason}`.toLowerCase().includes(flt.q)
const matchKind = d => flt.kind === 'all' || (flt.kind === 'allowed' ? d.allowed : flt.kind === 'blocked' ? !d.allowed : !d.allowed && d.reason === flt.kind)
const inView = d => !paused || d._seq <= pauseSeq

function feedRow(d) {
  return h('li', {}, h('button', { type: 'button', onclick: e => openDrawer(d, e.currentTarget) },
    h('time', {}, clock(d._ms)),
    h('span', { className: 'path', title: `${d.client} · cost ${d.cost}` }, `${d.method} ${d.path}`, h('i', {}, d.tenant)),
    h('span', { className: 'pill ' + (d.allowed ? '' : reasonCls(d.reason)) }, d.allowed ? 'ok' : d.reason)))
}

function renderChips() {
  const n = { all: 0, allowed: 0, blocked: 0 }
  for (const d of buf) {
    if (!inView(d) || !matchQ(d)) continue
    n.all++
    if (d.allowed) n.allowed++
    else { n.blocked++; n[d.reason] = (n[d.reason] || 0) + 1 }
  }
  const reasons = Object.keys(n).filter(k => !['all', 'allowed', 'blocked'].includes(k)).sort((a, b) => n[b] - n[a])
  if (!reasons.includes(flt.kind) && !['all', 'allowed', 'blocked'].includes(flt.kind)) reasons.push(flt.kind)
  const kinds = ['all', 'allowed', 'blocked', ...reasons]
  for (const [k, el] of chipEls) if (!kinds.includes(k)) { el.remove(); chipEls.delete(k) }
  const box = $('#chips')
  kinds.forEach((k, i) => {
    let el = chipEls.get(k)
    if (!el) {
      el = h('button', { className: 'chip', type: 'button', onclick: () => { flt.kind = k; renderFeed() } }, h('span', {}, k), h('span', { className: 'n' }))
      chipEls.set(k, el)
    }
    if (box.children[i] !== el) box.insertBefore(el, box.children[i] || null)
    el.setAttribute('aria-pressed', flt.kind === k)
    el.lastChild.textContent = fmt(n[k] || 0)
  })
}

function renderFeed() {
  const ul = $('#feed')
  const rows = []
  for (let i = buf.length - 1; i >= 0 && rows.length < SHOW; i--) if (inView(buf[i]) && matchQ(buf[i]) && matchKind(buf[i])) rows.push(buf[i])
  const keep = new Set(rows.map(d => d._seq))
  for (const [s, el] of els) if (!keep.has(s)) { el.remove(); els.delete(s) }
  let ref = ul.firstElementChild
  for (const d of rows) {
    let el = els.get(d._seq)
    if (!el) els.set(d._seq, el = feedRow(d))
    if (el === ref) ref = ref.nextElementSibling
    else ul.insertBefore(el, ref)
  }
  for (const [s, el] of els) el.firstChild.setAttribute('aria-current', s === sel)
  const empty = $('#feedEmpty')
  const state = rows.length ? '' : buf.length ? 'nomatch' : empty.dataset.s === 'err' ? 'err' : 'wait'
  empty.hidden = !state
  if (empty.dataset.s !== state) {
    empty.dataset.s = state
    if (state === 'nomatch') empty.replaceChildren('No decisions match this filter. ', h('button', { className: 'link', type: 'button', onclick: clearFilter }, 'Clear filter'))
    else if (state === 'wait') empty.textContent = 'Waiting for traffic.'
  }
  const bar = $('#feedBar')
  bar.hidden = !paused
  bar.textContent = `Paused. ${fmt(seq - pauseSeq)} new ${seq - pauseSeq === 1 ? 'decision' : 'decisions'} waiting.`
  renderChips()
}

function clearFilter() { flt.kind = 'all'; flt.q = ''; $('#q').value = ''; renderFeed() }
$('#q').oninput = e => { flt.q = e.target.value.trim().toLowerCase(); renderFeed() }
$('#feed').onkeydown = e => {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
  const li = e.target.closest('li')?.[e.key === 'ArrowDown' ? 'nextElementSibling' : 'previousElementSibling']
  if (li) { e.preventDefault(); li.firstChild.focus() }
}

function setPaused(on) {
  paused = on
  pauseSeq = seq
  const b = $('#pause')
  b.setAttribute('aria-pressed', on)
  b.replaceChildren(on ? 'Resume ' : 'Pause ', h('kbd', {}, 'p'))
  renderFeed()
}
$('#pause').onclick = () => setPaused(!paused)

function viewClient(c) {
  location.hash = '#/overview'
  flt.q = c.toLowerCase(); $('#q').value = c
  renderFeed()
}

function finding() {
  const cut = Date.now() - 60000
  const recent = buf.filter(d => d._ms > cut), blocked = recent.filter(d => !d.allowed)
  const top = key => { const c = {}; blocked.forEach(d => { c[d[key]] = (c[d[key]] || 0) + 1 }); return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0] }
  const alert = tenants.filter(t => t.monthlyLimit && 100 * t.monthlyUsed / t.monthlyLimit >= PLAN_ALERT)
  let plan = alert.length ? ` ${alert.map(t => t.tenant).join(', ')} ${alert.length === 1 ? 'is' : 'are'} past ${PLAN_ALERT}% of the monthly quota.` : ''
  if (orgInfo?.budget && 100 * orgInfo.used / orgInfo.budget >= PLAN_ALERT) plan += ` ${orgInfo.name || orgInfo.id} is past ${PLAN_ALERT}% of its shared budget.`
  if (!recent.length) return 'No requests in the last minute.' + plan
  if (!blocked.length) return `${fmt(recent.length)} requests in the last minute, none blocked.` + plan
  return `${fmt(blocked.length)} of ${fmt(recent.length)} requests blocked in the last minute, mostly ${top('reason')} from ${top('client')}.` + plan
}

// inspector
let drawerD, trigger
const dur = ns => {
  const ms = ns / 1e6
  return !ns ? '—' : ms < 1000 ? Math.round(ms) + ' ms' : ms < 60000 ? (ms / 1000).toFixed(1) + ' s' : `${Math.floor(ms / 60000)} m ${Math.round(ms % 60000 / 1000)} s`
}
const why = d => ({
  ok: 'Within limits. The request was passed through.',
  burst: `The client used up its ${d.tier} burst allowance. Wait ${dur(d.retryAfter)} for tokens to refill.`,
  monthly: `${d.tenant} has used its monthly quota on the ${d.tier} tier. It resets on the 1st (UTC).`,
  org_monthly: `The ${d.org} org has used its shared monthly budget, across all its tenants. It resets on the 1st (UTC).`,
  banned: `${d.client} is on the ban list${d.retryAfter ? ', which lifts in ' + dur(d.retryAfter) : ''}.`,
  error: 'The shared backend failed and the gateway is set to fail closed.',
}[d.reason] || '')

function openDrawer(d, from) {
  drawerD = d; sel = d._seq; trigger = from
  window.lpAI?.decision(d)
  const pill = $('#dPill')
  pill.className = 'pill ' + (d.allowed ? 'ok' : reasonCls(d.reason))
  pill.textContent = d.allowed ? 'allowed' : d.reason
  $('#dTitle').textContent = `${d.method} ${d.path}`
  $('#dWhy').textContent = why(d)
  const row = (k, v, sub) => h('div', {}, h('dt', {}, k), h('dd', {}, v, sub ? h('small', {}, sub) : null))
  const ms = String(d._ms % 1000).padStart(3, '0')
  $('#dList').replaceChildren(
    row('Time', `${clock(d._ms)}.${ms}`), row('Tenant', d.tenant || '—'), row('Org', d.org || '—', d.org ? 'shares one monthly budget' : null), row('Tier', d.tier || '—'), row('Client', d.client),
    row('Cost', fmt(d.cost), d.cost === 1 ? 'token' : 'tokens'),
    row('Lane', d.lane || '—', d.lane ? 'set this burst' : 'tier has no lanes'),
    row(d.reason === 'monthly' ? 'Monthly limit' : d.reason === 'org_monthly' ? 'Org budget' : 'Limit', d.limit ? fmt(d.limit) : '—'),
    row('Remaining', d.limit ? fmt(d.remaining) : '—', d.limit ? `${Math.round(100 * d.remaining / d.limit)}% of limit` : null),
    row('Retry after', dur(d.retryAfter)),
    row('Degraded', d.degraded ? 'yes' : 'no', d.degraded ? 'local fallback decided this' : null))
  const b = $('#dBan')
  b.disabled = isBanned(d.client)
  b.textContent = b.disabled ? 'Already banned' : 'Ban client 10 min'
  $('#drawer').hidden = false; $('#scrim').hidden = false
  document.body.dataset.drawer = ''
  $('#dClose').focus()
  renderFeed()
}

function closeDrawer() {
  if ($('#drawer').hidden) return
  $('#drawer').hidden = true; $('#scrim').hidden = true
  delete document.body.dataset.drawer
  sel = 0
  renderFeed()
  if (trigger?.isConnected) trigger.focus()
}
$('#dClose').onclick = $('#scrim').onclick = closeDrawer
$('#dBan').onclick = async () => {
  if (!await ban(drawerD.client, 10, 'manual (inspector)')) return
  $('#dBan').disabled = true
  $('#dBan').textContent = 'Already banned'
}
$('#dFilter').onclick = () => { const c = drawerD.client; closeDrawer(); viewClient(c) }
$('#dCopy').onclick = async () => {
  try { await navigator.clipboard.writeText(JSON.stringify(drawerD, (k, v) => (k[0] === '_' ? undefined : v), 2)); toast('Decision copied as JSON', 'ok') }
  catch { toast('Copy is blocked in this context', 'bad') }
}

// chart: canvas 2D, scaled by devicePixelRatio so lines stay crisp
const geo = { L: 36, R: 10, T: 10, B: 22 }
let hoverT = null, drawQueued = false
const css = () => { const s = getComputedStyle(document.documentElement); return k => s.getPropertyValue(k).trim() }
function niceStep(peak) {
  for (let p = 1; p <= 1e7; p *= 10) for (const m of [1, 2, 5]) if (Math.floor(peak / (m * p)) + 1 <= 4) return m * p
  return 1e7
}

function draw() {
  const c = $('#chart'), w = c.clientWidth, ht = c.clientHeight
  if (!w) return
  const dpr = devicePixelRatio || 1, bw = Math.round(w * dpr), bh = Math.round(ht * dpr)
  if (c.width !== bw || c.height !== bh) { c.width = bw; c.height = bh }
  const g = c.getContext('2d'), v = css()
  g.setTransform(bw / w, 0, 0, bh / ht, 0, 0)
  g.clearRect(0, 0, w, ht)
  const { L, R, T, B } = geo, pw = w - L - R, ph = ht - T - B
  const peakOf = k => series.reduce((m, p) => Math.max(m, p[k]), 0)
  const peak = Math.max(peakOf('allowed'), peakOf('blocked'))
  const step = niceStep(peak), top = Math.max(4, (Math.floor(peak / step) + 1) * step)
  const off = N - series.length
  const x = i => L + (i + off) / (N - 1) * pw
  const y = n => T + ph - n / top * ph
  geo.pw = pw; geo.off = off

  g.font = '11px "Geist Mono", ui-monospace, monospace'
  g.textBaseline = 'middle'; g.textAlign = 'right'
  for (let n = 0; n <= top; n += step) {
    const yy = Math.round(y(n)) + .5
    g.strokeStyle = n ? v('--line') : v('--control'); g.lineWidth = 1
    g.beginPath(); g.moveTo(L, yy); g.lineTo(w - R, yy); g.stroke()
    g.fillStyle = v('--muted'); g.fillText(fmt(n), L - 8, yy)
  }
  g.textBaseline = 'alphabetic'
  ;[['−2m', 119, 'left'], ['−90s', 90, 'center'], ['−60s', 60, 'center'], ['−30s', 30, 'center'], ['now', 0, 'right']].forEach(([t, s, al]) => {
    g.textAlign = al; g.fillStyle = v('--muted'); g.fillText(t, L + (119 - s) / 119 * pw, ht - 5)
  })

  g.save(); g.beginPath(); g.rect(L, T - 2, pw + R, ph + 4); g.clip()
  for (const [key, color, area] of [['allowed', v('--ok'), true], ['blocked', v('--bad'), false]]) {
    if (!series.length) break
    g.beginPath()
    series.forEach((p, i) => i ? g.lineTo(x(i), y(p[key])) : g.moveTo(x(i), y(p[key])))
    g.strokeStyle = color; g.lineWidth = 1.5; g.lineJoin = 'round'; g.stroke()
    if (area) {
      g.lineTo(x(series.length - 1), y(0)); g.lineTo(x(0), y(0)); g.closePath()
      g.globalAlpha = .1; g.fillStyle = color; g.fill(); g.globalAlpha = 1
    }
  }
  g.restore()

  const tip = $('#tip'), i = hoverT == null ? -1 : series.findIndex(p => p.t === hoverT)
  if (i < 0) { tip.hidden = true } else {
    const p = series[i], xx = Math.round(x(i)) + .5
    g.strokeStyle = v('--control'); g.beginPath(); g.moveTo(xx, T); g.lineTo(xx, T + ph); g.stroke()
    for (const [key, color] of [['allowed', v('--ok')], ['blocked', v('--bad')]]) {
      g.beginPath(); g.arc(xx, y(p[key]), 3.5, 0, 7)
      g.fillStyle = color; g.fill(); g.strokeStyle = v('--tile'); g.lineWidth = 2; g.stroke()
    }
    tip.hidden = false
    tip.replaceChildren(h('b', {}, clock(p.t * 1000)),
      h('span', {}, h('span', {}, h('i', { className: 'sw ok' }), 'allowed'), `${fmt(p.allowed)}/s`),
      h('span', {}, h('span', {}, h('i', { className: 'sw bad' }), 'blocked'), `${fmt(p.blocked)}/s`))
    tip.style.left = Math.max(0, xx + 14 + tip.offsetWidth > w ? xx - 14 - tip.offsetWidth : xx + 14) + 'px'
  }
  const pk = `Last 120 seconds · peak ${fmt(peakOf('allowed'))}/s allowed, ${fmt(peakOf('blocked'))}/s blocked`
  if ($('#peak').textContent !== pk) $('#peak').textContent = pk
}
const drawSoon = () => { drawQueued ||= requestAnimationFrame(() => { drawQueued = false; draw() }) }
new ResizeObserver(draw).observe($('#chart'))

function pointAt(clientX) {
  const r = $('#chart').getBoundingClientRect()
  const i = Math.round((clientX - r.left - geo.L) / geo.pw * (N - 1)) - geo.off
  hoverT = series[Math.min(series.length - 1, Math.max(0, i))]?.t ?? null
  drawSoon()
}
$('#chart').onpointermove = $('#chart').onpointerdown = e => pointAt(e.clientX)
$('#chart').onpointerleave = () => { if (document.activeElement !== $('#chart')) { hoverT = null; drawSoon() } }
$('#chart').onblur = () => { hoverT = null; drawSoon() }
$('#chart').onkeydown = e => {
  const moves = { ArrowLeft: -1, ArrowRight: 1 }
  let i = series.findIndex(p => p.t === hoverT)
  if (e.key === 'Escape') hoverT = null
  else if (e.key in moves) i = i < 0 ? series.length - 1 : Math.min(series.length - 1, Math.max(0, i + moves[e.key]))
  else if (e.key === 'Home') i = 0
  else if (e.key === 'End') i = series.length - 1
  else return
  e.preventDefault()
  if (e.key !== 'Escape') {
    hoverT = series[i].t
    $('#chartLive').textContent = `${clock(hoverT * 1000)}: ${series[i].allowed} allowed, ${series[i].blocked} blocked per second`
  }
  draw()
}

// policy
const ta = $('#policy')
let saved = ''
function policyMsg(text, kind = '') {
  const m = $('#policyMsg')
  m.textContent = text
  m.className = 'msg ' + kind
  ta.setAttribute('aria-invalid', kind === 'err')
}

function check() {
  const dirty = ta.value !== saved
  const s = $('#dirty')
  s.className = 'state' + (dirty ? ' dirty' : '')
  s.textContent = dirty ? 'Unsaved changes' : 'Matches the running policy'
  let bad = ''
  try { JSON.parse(ta.value) } catch (e) { bad = e.message }
  if (bad && dirty) policyMsg('Invalid JSON: ' + bad, 'err')
  $('#policySave').disabled = !dirty || !!bad
  $('#policyLoad').disabled = !dirty
  $('#policyFormat').disabled = !!bad
  $('#policySave').title = bad ? 'Fix the JSON first' : dirty ? '' : 'No changes to save'
}

function applyPolicy(cfg) {
  policyCfg = cfg
  saved = JSON.stringify(cfg, null, 2)
  ta.value = saved
  ta.disabled = false
  policyMsg('')
  check(); renderRoutes(); renderTiers(); renderTenants()
}

async function loadPolicy() {
  try { applyPolicy(await api('policy')) }
  catch (err) { policyMsg(`Couldn't load the policy: ${err.message}. Use Revert to retry.`, 'err'); $('#policyLoad').disabled = false }
}

ta.oninput = () => { policyMsg(''); check() }
$('#policyLoad').onclick = loadPolicy
$('#policyFormat').onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); check() } catch {} }
async function savePolicy() {
  if ($('#policySave').disabled) return
  let body
  try { body = JSON.stringify(JSON.parse(ta.value)) } catch { return check() }
  $('#policySave').disabled = true
  try {
    applyPolicy(await api('policy', { method: 'PUT', body }))
    toast('Policy saved. New limits apply from the next request.', 'ok')
  } catch (err) {
    policyMsg(err.message, 'err')
    toast('Policy rejected. The editor shows what to fix.', 'bad')
    check()
    ta.focus()
  }
}
$('#policySave').onclick = savePolicy
ta.onkeydown = e => { if ((e.metaKey || e.ctrlKey) && e.key === 's') { e.preventDefault(); savePolicy() } }
addEventListener('beforeunload', e => { if (saved && ta.value !== saved) e.preventDefault() })

// try it (demo mode only; demo routes live at the origin root)
const shown = ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset', 'Retry-After']
async function fire(kind, btn) {
  const key = $('#apiKey').value.trim()
  const opts = { method: kind === 'generate' ? 'POST' : 'GET', headers: key ? { 'X-API-Key': key } : {} }
  const url = kind === 'generate' ? '/v1/generate' : '/v1/ping'
  const one = async () => { const r = await fetch(url, opts); return { r, text: await r.text() } }
  const out = $('#tryOut')
  btn.disabled = true
  try {
    if (kind !== 'flood') {
      const { r, text } = await one()
      out.textContent = describe(opts.method, url, r, text)
      return
    }
    const all = await Promise.all(Array.from({ length: 30 }, one))
    const ok = all.filter(x => x.r.ok).length
    const last = all.find(x => x.r.status === 429) || all[all.length - 1]
    out.textContent = `30 requests: ${ok} allowed, ${30 - ok} blocked\n\n` + describe(opts.method, url, last.r, last.text)
  } catch (err) { out.textContent = 'Request failed: ' + err.message }
  finally { btn.disabled = false }
}
function describe(method, url, r, text) {
  const hdrs = shown.map(k => r.headers.get(k) != null && `${k}: ${r.headers.get(k)}`).filter(Boolean)
  return `${method} ${url} -> ${r.status}\n${hdrs.join('\n')}\n\n${text.slice(0, 600)}`
}
$$('[data-try]').forEach(b => { b.onclick = () => fire(b.dataset.try, b) })

// globe: a ping per live decision, near a city picked by a hash of the client id (not geography)
const globe = clientGlobe($('#globe'))

// command palette: a combobox over a listbox; the input keeps focus, arrows move the active option
const pal = $('#palette'), palQ = $('#palQ'), palList = $('#palList')
let palItems = [], palAt = 0, palFrom = null

function commands(raw) {
  const q = raw.toLowerCase(), go = (v, label, key) => ({ group: 'Go to', label, key, run: () => { location.hash = '#/' + v } })
  const vs = shownViews(), labels = { overview: 'Overview', clients: 'Clients and bans', org: isSuper() ? 'Orgs, tenants and keys' : 'Org, tenants and members', ask: 'Ask and explain', policy: 'Open policy editor', try: 'Try it' }
  const user = me && me.user !== 'admin'
  const all = [
    ...vs.map((v, i) => go(v, labels[v], String(i + 1))),
    { group: 'Feed', label: paused ? 'Resume the decision feed' : 'Pause the decision feed', key: 'p', run: () => setPaused(!paused) },
    { group: 'Feed', label: 'Filter decisions', key: '/', run: () => { location.hash = '#/overview'; route(); $('#q').focus() } },
    ...(isSuper() ? [{ group: 'Clients', label: 'Ban an IP or CIDR…', hint: 'type it', keep: true, run: () => { palQ.value = 'ban '; palRender() } }] : []),
    ...(isSuper() ? orgs.map(o => ({ group: 'Org in view', label: 'View ' + (o.name || o.id), hint: o.id, run: () => switchOrg(o.id) })).concat(scopeOrg ? [{ group: 'Org in view', label: 'View all orgs', run: () => switchOrg('') }] : []) : []),
    { group: 'General', label: `Switch to ${isDark() ? 'light' : 'dark'} theme`, run: toggleTheme },
    { group: 'General', label: 'Keyboard shortcuts', key: '?', run: () => $('#help').showModal() },
    ...(user ? [{ group: 'Account', label: 'Change password', run: () => openPw() }, { group: 'Account', label: 'Sign out everywhere', hint: 'every session', run: revokeAll }] : []),
    { group: 'General', label: 'Sign out', run: logout },
  ]
  const target = raw.replace(/^ban\s+/i, '').trim()
  const banOnly = /^ban\s+\S/i.test(raw)
  const found = banOnly ? [] : all.filter(c => !q || c.label.toLowerCase().includes(q))
  if (!isSuper() || !target || /\s/.test(target) || (!banOnly && found.length && target.length < 3)) return found
  const t = target.toLowerCase(), banItem = (id, hint) => ({ group: 'Ban for 10 minutes', label: 'Ban ' + id, hint, run: () => ban(id, 10, 'manual (palette)') })
  const known = clients.filter(c => !isBanned(c.client) && c.client.toLowerCase().includes(t)).slice(0, 5)
  const bans = known.map(c => banItem(c.client, c.label || 'client'))
  const typed = parseTarget(target)
  if (typed.error) {
    // only explain when the user is clearly banning; a plain search just shows what matched
    if (banOnly && !known.length) bans.push({ group: 'Ban for 10 minutes', label: typed.error, hint: 'not banned', disabled: true, run: () => {} })
  } else if (typed.cidr) {
    if (banned.has(typed.text)) bans.push({ group: 'Ban for 10 minutes', label: typed.text + ' is already banned', disabled: true, run: () => {} })
    else {
      const n = clients.filter(c => inRange(typed, c.client)).length
      bans.push(banItem(typed.text, rangeText(typed) + (n ? ` · ${n} active` : '') + (typed.masked ? ' · masked' : '')))
    }
  } else if (!known.some(c => c.client.toLowerCase() === typed.text) && !isBanned(typed.text)) bans.push(banItem(typed.text, 'as typed'))
  return [...found, ...bans]
}

function palRender() {
  palItems = commands(palQ.value)
  palAt = Math.min(palAt, Math.max(0, palItems.length - 1))
  let g = ''
  palList.replaceChildren(...palItems.flatMap((c, i) => {
    const li = h('li', { id: 'pc' + i, role: 'option', className: 'pitem' + (c.disabled ? ' off' : ''), 'aria-disabled': !!c.disabled, onclick: () => palRun(i), onpointermove: () => palMove(i) },
      h('span', {}, c.label), c.hint ? h('small', {}, c.hint) : null, c.key ? h('kbd', {}, c.key) : null)
    const out = c.group === g ? [li] : [h('li', { role: 'presentation', className: 'pgroup' }, c.group), li]
    g = c.group
    return out
  }))
  if (!palItems.length) palList.append(h('li', { role: 'presentation', className: 'pempty' }, 'No matching command.'))
  palMove(palAt)
}

function palMove(i) {
  if (!palItems.length) return palQ.removeAttribute('aria-activedescendant')
  palAt = (i + palItems.length) % palItems.length
  $$('.pitem').forEach((el, j) => el.setAttribute('aria-selected', j === palAt))
  palQ.setAttribute('aria-activedescendant', 'pc' + palAt)
  $('#pc' + palAt).scrollIntoView({ block: 'nearest' })
}

function palRun(i) {
  const c = palItems[i]
  if (!c || c.disabled) return
  // restore focus before running, so the command can move it (close's own event fires later)
  if (!c.keep) { pal.close(); palFrom?.focus(); palFrom = null }
  c.run()
}

function openPalette() {
  if (pal.open) return pal.close()
  if ($('#help').open) $('#help').close()
  palFrom = document.activeElement
  palQ.value = ''; palAt = 0
  palRender()
  pal.showModal()
  palQ.focus()
}
palQ.oninput = () => { palAt = 0; palRender() }
palQ.onkeydown = e => {
  const k = e.key
  if (k === 'ArrowDown' || k === 'ArrowUp') palMove(palAt + (k === 'ArrowDown' ? 1 : -1))
  else if (k === 'Home' || k === 'End') palMove(k === 'Home' ? 0 : palItems.length - 1)
  else if (k === 'Enter') palRun(palAt)
  else if (k !== 'Tab') return // the input is the only stop, so Tab stays put
  e.preventDefault()
}
pal.onclick = e => { if (e.target === pal) pal.close() }
pal.onclose = () => { if (palFrom?.isConnected) palFrom.focus(); palFrom = null }
$('#cmdk').onclick = openPalette

// keyboard
$('#helpBtn').onclick = () => $('#help').showModal()
addEventListener('keydown', e => {
  if (token && (e.metaKey || e.ctrlKey) && e.key?.toLowerCase() === 'k') { e.preventDefault(); return openPalette() }
  if (!token || $('#help').open || pal.open) return
  if (e.key === 'Escape' && !$('#drawer').hidden) return closeDrawer()
  if (e.metaKey || e.ctrlKey || e.altKey) return
  if (e.target.matches?.('input, textarea, select, [contenteditable]')) {
    if (e.key === 'Escape' && e.target.id === 'q') { clearFilter(); e.target.blur() }
    return
  }
  const tabs = shownViews()
  if (e.key === '/') { e.preventDefault(); location.hash = '#/overview'; route(); $('#q').focus() }
  else if (e.key === 'p') setPaused(!paused)
  else if (e.key === '?') $('#help').showModal()
  else if (/^[1-9]$/.test(e.key) && tabs[e.key - 1]) location.hash = '#/' + tabs[e.key - 1]
})

// org view: the shared budget, tenants and keys, members; for the superadmin across all orgs, the orgs
let orgs = [], orgInfo = null, otenants = [], members = null

async function loadOrgs() {
  if (!isSuper()) return
  try { orgs = await api('orgs') } catch { return }
  const pick = $('#orgPick')
  pick.replaceChildren(h('option', { value: '' }, 'All orgs'), ...orgs.map(o => h('option', { value: o.id }, o.name || o.id)))
  if (scopeOrg && !orgs.some(o => o.id === scopeOrg)) return switchOrg('')
  pick.value = scopeOrg
  renderOrgs()
}

function loadOrgView() {
  const one = !!viewOrg(), sup = isSuper()
  const name = one ? (sup ? orgs.find(o => o.id === scopeOrg)?.name : me.orgName) || viewOrg() : 'every org'
  $('#h-org').replaceChildren(one ? 'Org, ' : 'Orgs, ', h('em', {}, one ? name : 'all of them'))
  $('#orgSub').textContent = one ? `Tenants, API keys${can('owner') ? ', members' : ''} and the shared monthly budget of ${name}.` : 'Every org on this gateway. Pick one to manage its members, tenants and budget.'
  $('#orgsCard').hidden = !sup || one
  $('#budgetCard').hidden = !one
  $('#tenantsCard').className = 'card' + (one ? ' c7' : '')
  $('#membersCard').hidden = !one || !can('owner')
  $('#budgetForm').hidden = !can('owner')
  $('#tenantForm').hidden = !one || !can('admin')
  $('#otNote').textContent = one ? 'Keys made here are stored as a hash: the key itself is shown once.' : 'Every tenant. Switch to an org to add tenants and keys in it; tenants from the policy file are managed there.'
  if (sup) loadOrgs()
  renderBudget(); renderOrgTenants(true)
  if (one && can('owner')) loadMembers()
}

function renderOrgs() {
  const rows = orgs.map(o => h('div', { className: 'r' },
    h('div', {}, h('button', { className: 'link mono', type: 'button', title: 'View ' + o.id, onclick: () => switchOrg(o.id) }, o.name || o.id), col('sub2', o.id)),
    o.budget ? gauge(o.used, o.budget, o.id + ' shared budget', 'budget used up') : col('sub2', `No budget · ${fmt(o.used)} used`),
    col('num mono', fmt(o.members)), col('num mono', fmt(o.tenants)),
    h('button', { className: 'btn small', type: 'button', 'aria-label': 'Delete org ' + o.id, onclick: () => deleteOrg(o) }, 'Delete')))
  list($('#orgs'), head(['Org', 'Budget this month', 'Members', 'Tenants', ''], [2, 3]), rows, 'No orgs yet. Create the first one below.')
  $('#orgsCount').textContent = `${orgs.length} ${orgs.length === 1 ? 'org' : 'orgs'}`
}

async function deleteOrg(o) {
  if (!confirm(`Delete ${o.name || o.id} and its ${o.members} members? Its tenants must be gone first.`)) return
  try { await api('orgs/' + enc(o.id), { method: 'DELETE' }); toast('Deleted org ' + o.id, 'ok'); loadOrgs() }
  catch (err) { toast(err.message, 'bad') }
}

$('#orgForm').onsubmit = async e => {
  e.preventDefault()
  const f = e.target, body = { name: f.name.value.trim(), id: f.id.value.trim() || undefined, budget: f.budget.value ? Number(f.budget.value) : undefined }
  $('#orgMsg').textContent = ''
  if (!body.name) { $('#orgMsg').textContent = 'An org needs a name.'; return f.name.focus() }
  try {
    const o = await api('orgs', { method: 'POST', body: JSON.stringify(body) })
    toast('Created org ' + o.id + '. Add its first owner from its page.', 'ok')
    f.reset()
    await loadOrgs()
  } catch (err) { $('#orgMsg').textContent = err.message }
}

function renderBudget() {
  if (!$('#budgetCard') || !viewOrg()) return
  const o = orgInfo, box = $('#budget')
  const now = new Date()
  $('#budgetResets').textContent = 'Resets in ' + Math.ceil((Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1) - now) / 864e5) + ' d (UTC)'
  if (!o) return box.replaceChildren(h('div', { className: 'skel', 'aria-hidden': 'true' }, h('i'), h('i')))
  box.replaceChildren(
    h('div', { className: 'kpi bnum' }, h('span', {}, 'Used this month'), h('b', {}, fmt(o.used), h('small', {}, ' units'))),
    o.budget ? gauge(o.used, o.budget, o.id + ' shared monthly budget', 'budget used up') : h('p', { className: 'meta' }, 'No budget: spend is counted, nothing is capped. Set one and it covers this whole month, spend so far included.'))
  const inp = $('#budgetForm').budget
  if (document.activeElement !== inp) inp.placeholder = o.budget ? String(o.budget) : '0 for none'
  $('#budgetClear').hidden = !o.budget
}

async function setBudget(budget) {
  $('#budgetMsg').textContent = ''
  if (!(Number.isInteger(budget) && budget >= 0)) { $('#budgetMsg').textContent = 'A budget is a whole number of units, 0 for none.'; return }
  try {
    orgInfo = await api('orgs/' + enc(viewOrg()), { method: 'PATCH', body: JSON.stringify({ budget }) })
    toast(budget ? `Budget set to ${fmt(budget)} units a month` : 'Budget removed', 'ok')
    $('#budgetForm').reset()
    renderBudget(); renderTenants()
  } catch (err) { $('#budgetMsg').textContent = err.message }
}
$('#budgetForm').onsubmit = e => { e.preventDefault(); const v = e.target.budget.value; setBudget(v === '' ? NaN : Number(v)) }
$('#budgetClear').onclick = () => setBudget(0)

function renderOrgTenants(force) {
  const box = $('#otenants')
  if (!loaded.otenants) return
  const sig = JSON.stringify([otenants, me?.role, scopeOrg])
  if (!force && box.dataset.sig === sig) return // re-render only on change, so focus and clicks survive the refresh
  box.dataset.sig = sig
  const all = isSuper() && !scopeOrg, edit = can('admin')
  const rows = otenants.map(t => {
    const keys = (t.keys || []).map(k => h('span', { className: 'kchip mono', title: 'Created ' + new Date(k.created).toLocaleString() }, k.prefix + '…',
      edit ? h('button', { className: 'x', type: 'button', 'aria-label': `Revoke key ${k.prefix} of ${t.id}`, title: 'Revoke this key', onclick: () => revokeKey(t, k) }, '×') : null))
    return h('div', { className: 'r' },
      h('div', {}, col('mono ell', t.id), col('sub2', [all && (t.org ? 'org ' + t.org : 'no org'), t.tier, t.managed ? 'dashboard' : t.pinned ? 'policy, org pinned' : 'policy'].filter(Boolean).join(' · '))),
      h('div', { className: 'kchips' }, ...(keys.length ? keys : [col('sub2', t.managed ? 'No keys yet' : 'Keys in the policy')])),
      h('div', { className: 'acts' }, ...(edit && t.managed ? [
        h('button', { className: 'btn small', type: 'button', onclick: () => newKey(t) }, 'New key'),
        h('button', { className: 'btn small ghost', type: 'button', 'aria-label': 'Delete tenant ' + t.id, onclick: () => deleteTenant(t) }, 'Delete')] : [])))
  })
  list(box, head(['Tenant', 'Keys', '']), rows, viewOrg() ? 'No tenants in this org yet.' : 'No tenants yet.')
  $('#otCount').textContent = `${otenants.length} ${otenants.length === 1 ? 'tenant' : 'tenants'}`
}

async function reloadTenants() {
  try { otenants = await api(orgQ('tenants')); loaded.otenants = true; renderOrgTenants(true) } catch (err) { toast(err.message, 'bad') }
}

$('#tenantForm').onsubmit = async e => {
  e.preventDefault()
  const f = e.target, id = f.id.value.trim()
  $('#tenantMsg').textContent = ''
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) { $('#tenantMsg').textContent = 'A tenant id is 1 to 64 letters, digits, dots, dashes and underscores.'; return f.id.focus() }
  try {
    await api('tenants', { method: 'POST', body: JSON.stringify({ id, tier: f.tier.value, org: viewOrg() }) })
    toast(`Added tenant ${id}. Make it a key next.`, 'ok')
    f.id.value = ''
    reloadTenants()
  } catch (err) { $('#tenantMsg').textContent = err.message }
}

async function deleteTenant(t) {
  if (!confirm(`Delete tenant ${t.id} and its ${(t.keys || []).length} keys? Requests with them become anonymous at once.`)) return
  try { await api('tenants/' + enc(t.id), { method: 'DELETE' }); toast('Deleted tenant ' + t.id, 'ok'); reloadTenants() }
  catch (err) { toast(err.message, 'bad') }
}

async function newKey(t) {
  try {
    const k = await api('tenants/' + enc(t.id) + '/keys', { method: 'POST' })
    showSecret('New API key', `For ${t.id}. Send it as the X-Api-Key header; every replica accepts it now.`, k.key, 'Copy it now: it is stored only as a hash, so you won\'t see it again.')
    reloadTenants()
  } catch (err) { toast('New key failed: ' + err.message, 'bad') }
}

async function revokeKey(t, k) {
  if (!confirm(`Revoke key ${k.prefix}… of ${t.id}? Requests with it become anonymous at once.`)) return
  try { await api(`tenants/${enc(t.id)}/keys/${enc(k.id)}`, { method: 'DELETE' }); toast(`Revoked ${k.prefix}…`, 'ok'); reloadTenants() }
  catch (err) { toast(err.message, 'bad') }
}

// one dialog for anything shown once: a new key, a generated password
let secretFrom
function showSecret(title, why, value, note) {
  secretFrom = document.activeElement
  $('#secretTitle').textContent = title
  $('#secretWhy').textContent = why
  $('#secretVal').textContent = value
  $('#secret').querySelector('.meta').textContent = note
  $('#secret').showModal()
  $('#secretCopy').focus()
}
$('#secret').onclose = () => { $('#secretVal').textContent = ''; if (secretFrom?.isConnected) secretFrom.focus() }
$('#secretCopy').onclick = async () => {
  try { await navigator.clipboard.writeText($('#secretVal').textContent); toast('Copied', 'ok') }
  catch { toast('Copy is blocked here: select the text instead', 'bad') }
}

async function loadMembers() {
  try { members = await api(`orgs/${enc(viewOrg())}/members`) } catch (err) { members = null; return failed('members', 'members', err) }
  renderMembers()
}

function renderMembers() {
  if (!members) return
  const roles = ['viewer', 'admin', 'owner']
  const rows = members.map(m => h('div', { className: 'r' },
    h('div', {}, col('mono ell', m.email), col('sub2', (m.id === me.user ? 'you · ' : '') + 'since ' + new Date(m.created).toLocaleDateString())),
    h('label', { className: 'sr', htmlFor: 'role-' + m.id }, 'Role of ' + m.email),
    h('select', { id: 'role-' + m.id, className: 'pick', onchange: e => setRole(m, e.target) }, ...roles.map(r => h('option', { value: r, selected: r === m.role }, r))),
    h('div', { className: 'acts' },
      h('button', { className: 'btn small', type: 'button', title: 'End every session ' + m.email + ' has', onclick: () => revokeMember(m) }, 'Sign out'),
      h('button', { className: 'btn small ghost', type: 'button', 'aria-label': 'Remove ' + m.email, onclick: () => removeMember(m) }, 'Remove'))))
  list($('#members'), head(['Member', 'Role', '']), rows, 'No members yet: add the first owner below.')
  $('#memCount').textContent = `${members.length} ${members.length === 1 ? 'member' : 'members'}`
}

const memberPath = m => `orgs/${enc(viewOrg())}/members/${enc(m.id)}`
async function setRole(m, sel) {
  try {
    await api(memberPath(m), { method: 'PATCH', body: JSON.stringify({ role: sel.value }) })
    toast(`${m.email} is now ${sel.value}; their sessions ended`, 'ok')
    if (m.id === me.user) return logout() // our own token carried the old role
    loadMembers()
  } catch (err) { sel.value = m.role; toast(err.message, 'bad') }
}
async function revokeMember(m) {
  try {
    await api(memberPath(m) + '/revoke', { method: 'POST' })
    if (m.id === me.user) return logout()
    toast(`Signed ${m.email} out everywhere`, 'ok')
  } catch (err) { toast(err.message, 'bad') }
}
async function removeMember(m) {
  if (!confirm(`Remove ${m.email} from the org? Their sessions end at once.`)) return
  try {
    await api(memberPath(m), { method: 'DELETE' })
    if (m.id === me.user) return logout()
    toast('Removed ' + m.email, 'ok'); loadMembers()
  } catch (err) { toast(err.message, 'bad') }
}

$('#memberForm').onsubmit = async e => {
  e.preventDefault()
  const f = e.target, body = { email: f.email.value.trim(), role: f.role.value, password: f.password.value }
  $('#memberMsg').textContent = ''
  if (!body.email.includes('@')) { $('#memberMsg').textContent = 'Enter an email address.'; return f.email.focus() }
  if (body.password && body.password.length < 10) { $('#memberMsg').textContent = 'A password needs at least 10 characters, or leave it empty to generate one.'; return f.password.focus() }
  try {
    const u = await api(`orgs/${enc(viewOrg())}/members`, { method: 'POST', body: JSON.stringify(body) })
    f.reset()
    if (u.password) showSecret('Account created', `${u.email} can sign in as ${u.role} with this password, and change it from the command palette.`, u.password, 'Pass it on now: it is stored only as a hash, so you won\'t see it again.')
    else toast(`Added ${u.email} as ${u.role}`, 'ok')
    loadMembers()
  } catch (err) { $('#memberMsg').textContent = err.message }
}

// account
function openPw() { $('#pwForm').reset(); $('#pwMsg').textContent = ''; $('#pwDlg').showModal(); $('#pwForm').current.focus() }
$('#pwCancel').onclick = () => $('#pwDlg').close()
$('#pwForm').onsubmit = async e => {
  e.preventDefault()
  const f = e.target
  if (f.password.value.length < 10) { $('#pwMsg').textContent = 'The new password needs at least 10 characters.'; return f.password.focus() }
  try {
    signedIn(await api('me/password', { method: 'PUT', body: JSON.stringify({ current: f.current.value, password: f.password.value }) }))
    $('#pwDlg').close()
    connect()
    toast('Password changed. Your other sessions ended.', 'ok')
  } catch (err) { $('#pwMsg').textContent = err.message }
}
async function revokeAll() {
  if (!confirm('Sign out of every session, this one included?')) return
  try { await api('me/revoke', { method: 'POST' }) } catch {}
  logout()
}

api('login').then(o => { signupOn = !!o.signup; if (!token) setMode(loginMode) }).catch(() => {})
token ? start() : show(false)
