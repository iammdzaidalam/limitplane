const $ = s => document.querySelector(s)
const N = 120
const fmt = n => (n ?? 0).toLocaleString()
const proxied = location.pathname.includes('/_limitplane')
const labels = { human: 'ok', bot: 'bad', crawler: 'info', retry_bug: 'warn', warming: '' }

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) k in e ? (e[k] = v) : e.setAttribute(k, v)
  e.append(...kids.filter(k => k != null))
  return e
}

const session = {
  get() { try { return sessionStorage.getItem('lp-token') } catch { return null } },
  set(v) { try { v ? sessionStorage.setItem('lp-token', v) : sessionStorage.removeItem('lp-token') } catch {} },
}
let token = session.get()

async function api(path, opts = {}) {
  const r = await fetch('api/' + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) },
  })
  if (r.status === 401 && path !== 'login') { logout(); throw new Error('session expired') }
  const text = await r.text()
  let body = text
  try { body = JSON.parse(text) } catch {}
  if (!r.ok) throw new Error(body?.message || body?.error || text || r.statusText)
  return body
}

// theme
$('#theme').onclick = () => {
  const root = document.documentElement
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches
  root.dataset.theme = dark ? 'light' : 'dark'
  try { localStorage.setItem('lp-theme', root.dataset.theme) } catch {}
  draw()
}

// auth
$('#loginForm').onsubmit = async e => {
  e.preventDefault()
  $('#loginMsg').textContent = ''
  try {
    const r = await api('login', { method: 'POST', body: JSON.stringify({ key: $('#key').value }) })
    token = r.token
    session.set(token)
    start()
  } catch (err) {
    $('#loginMsg').textContent = err.message || 'Sign in failed.'
  }
}
$('#logout').onclick = () => logout()

let timers = [], es
function logout() {
  token = null
  session.set(null)
  timers.forEach(clearInterval)
  timers = []
  es?.close()
  es = null
  show(false)
}

function show(authed) {
  $('#login').hidden = authed
  $('#app').hidden = !authed
  $('#logout').hidden = !authed
  $('#live').hidden = !authed
  $('#backend').hidden = !authed
  if (!authed) $('#key').focus()
}

function start() {
  show(true)
  $('#try').hidden = proxied
  refresh(true)
  loadPolicy()
  api('audit?limit=30').then(a => a.reverse().forEach(feedRow)).catch(() => {})
  connect()
  timers.push(setInterval(refresh, 4000), setInterval(() => { advance(); draw() }, 1000))
}

// stats
let series = []
let totals = { total: 0, allowed: 0, blocked: 0 }

function advance(now = Math.floor(Date.now() / 1000)) {
  const last = series.length ? series[series.length - 1].t : now - N
  for (let t = Math.max(last + 1, now - N + 1); t <= now; t++) series.push({ t, allowed: 0, blocked: 0 })
  if (series.length > N) series = series.slice(-N)
}

async function refresh(seed) {
  try {
    const [s, clients, bans] = await Promise.all([api('stats'), api('clients'), api('bans')])
    totals = { total: s.total, allowed: s.allowed, blocked: s.blocked }
    renderTotals()
    const b = $('#backend')
    b.className = 'badge ' + (s.degraded ? 'warn' : 'info')
    b.textContent = s.backend + (s.degraded ? ' · degraded' : '')
    if (seed === true) { series = (s.series || []).map(p => ({ ...p })); advance(); draw() }
    renderTenants(s.tenants || [])
    renderClients(clients || [])
    renderBans(bans || [])
  } catch (err) {
    console.warn('refresh:', err.message)
  }
}

function renderTotals() {
  $('#kTotal').textContent = fmt(totals.total)
  $('#kAllowed').textContent = fmt(totals.allowed)
  $('#kBlocked').textContent = fmt(totals.blocked)
  $('#kRate').textContent = totals.total ? (100 * totals.blocked / totals.total).toFixed(1) + '%' : '0%'
}

function fill(tbody, rows, cols, empty) {
  tbody.replaceChildren(...(rows.length ? rows : [h('tr', {}, h('td', { colSpan: cols, className: 'empty' }, empty))]))
}

function renderTenants(list) {
  fill($('#tenants'), list.map(t => {
    const pct = t.monthlyLimit ? Math.min(100, 100 * t.monthlyUsed / t.monthlyLimit) : 0
    const bar = h('div', { className: 'bar' + (pct >= 95 ? ' bad' : pct >= 80 ? ' warn' : ''), title: pct.toFixed(1) + '%' }, h('i', { style: `width:${pct}%` }))
    return h('tr', {},
      h('td', { className: 'mono' }, t.tenant), h('td', {}, t.tier),
      h('td', { className: 'num' }, fmt(t.allowed)), h('td', { className: 'num' }, fmt(t.blocked)),
      h('td', {}, t.monthlyLimit ? bar : h('span', { className: 'empty' }, 'no cap'),
        t.monthlyLimit ? h('div', { className: 'mono', style: 'font-size:11px;color:var(--muted)' }, `${fmt(t.monthlyUsed)} / ${fmt(t.monthlyLimit)}`) : null))
  }), 5, 'No tenants yet.')
}

function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000))
  return isNaN(s) ? '' : s < 60 ? s + 's ago' : Math.round(s / 60) + 'm ago'
}

function renderClients(list) {
  fill($('#clients'), list.map(c => h('tr', {},
    h('td', { className: 'mono' }, c.client),
    h('td', {}, h('span', { className: 'badge ' + (labels[c.label] ?? '') }, c.label || 'unknown')),
    h('td', { className: 'num' }, (c.rps ?? 0).toFixed(1)),
    h('td', { className: 'num' }, ((c.blockRatio ?? 0) * 100).toFixed(0) + '%'),
    h('td', {}, ago(c.lastSeen)),
    h('td', {}, h('button', { className: 'btn small', type: 'button', onclick: () => ban(c.client, 10, 'manual') }, 'Ban')),
  )), 6, 'No clients yet.')
}

function renderBans(list) {
  fill($('#bans'), list.map(b => h('tr', {},
    h('td', { className: 'mono' }, b.client),
    h('td', {}, new Date(b.until).toLocaleTimeString()),
    h('td', {}, b.reason || ''),
    h('td', {}, h('button', { className: 'btn small', type: 'button', onclick: () => unban(b.client) }, 'Unban')),
  )), 4, 'Nobody is banned.')
}

async function ban(client, minutes, reason) {
  $('#banMsg').textContent = ''
  try {
    await api('bans', { method: 'POST', body: JSON.stringify({ client, minutes, reason }) })
    refresh()
  } catch (err) { $('#banMsg').textContent = err.message }
}

async function unban(client) {
  try { await api('bans/' + encodeURIComponent(client), { method: 'DELETE' }); refresh() }
  catch (err) { $('#banMsg').textContent = err.message }
}

$('#banForm').onsubmit = e => {
  e.preventDefault()
  const f = new FormData(e.target)
  ban(f.get('client').trim(), Number(f.get('minutes')) || 10, f.get('reason') || 'manual')
  e.target.reset()
}

// live events
let backoff = 1000
function connect() {
  es?.close()
  setLive(false)
  es = new EventSource('api/events?token=' + encodeURIComponent(token))
  es.onopen = () => { backoff = 1000; setLive(true); refresh(true) }
  es.addEventListener('decision', e => onDecision(JSON.parse(e.data)))
  es.addEventListener('ban', () => refresh())
  es.onerror = () => {
    es.close()
    setLive(false)
    if (!token) return
    // EventSource hides the status code, so probe once to catch an expired token.
    api('stats').catch(() => {})
    setTimeout(() => token && connect(), backoff)
    backoff = Math.min(backoff * 2, 30000)
  }
}

function setLive(on) {
  const l = $('#live')
  l.className = 'badge ' + (on ? 'ok live' : 'warn')
  l.lastChild.textContent = on ? 'live' : 'reconnecting'
}

function onDecision(d) {
  totals.total++
  d.allowed ? totals.allowed++ : totals.blocked++
  renderTotals()
  const t = Math.floor(Date.parse(d.time) / 1000)
  advance()
  const b = series.find(p => p.t === t) || series[series.length - 1]
  if (b) d.allowed ? b.allowed++ : b.blocked++

  feedRow(d)
}

function feedRow(d) {
  $('#feedEmpty').hidden = true
  const feed = $('#feed')
  const cls = d.allowed ? 'ok' : d.reason === 'banned' ? 'bad' : 'warn'
  feed.prepend(h('li', {},
    h('time', {}, new Date(d.time).toLocaleTimeString([], { hour12: false })),
    h('span', { className: 'path', title: `${d.client} · cost ${d.cost}` }, `${d.method} ${d.path} `, h('span', { style: 'color:var(--muted)' }, d.tenant)),
    h('span', { className: 'badge ' + cls }, d.allowed ? 'ok' : d.reason)))
  while (feed.children.length > 60) feed.lastChild.remove()
}

// chart
function draw() {
  const c = $('#chart')
  if (!c.clientWidth) return
  const dpr = devicePixelRatio || 1, w = c.clientWidth, ht = c.clientHeight
  if (c.width !== w * dpr || c.height !== ht * dpr) { c.width = w * dpr; c.height = ht * dpr }
  const g = c.getContext('2d')
  g.setTransform(dpr, 0, 0, dpr, 0, 0)
  g.clearRect(0, 0, w, ht)
  const css = getComputedStyle(document.documentElement)
  const v = k => css.getPropertyValue(k).trim()
  const max = Math.max(4, ...series.map(p => Math.max(p.allowed, p.blocked)))
  const off = N - series.length
  const x = i => ((i + off) / (N - 1)) * w
  const y = n => ht - 16 - (n / max) * (ht - 30)

  g.strokeStyle = v('--line'); g.lineWidth = 1
  for (const n of [0, max / 2, max]) { g.beginPath(); g.moveTo(0, y(n)); g.lineTo(w, y(n)); g.stroke() }
  g.fillStyle = v('--muted'); g.font = '11px "Geist Mono", monospace'
  g.fillText(Math.round(max) + '/s', 4, y(max) - 4)
  g.fillText('-120s', 4, ht - 2)
  g.fillText('now', w - 24, ht - 2)

  for (const [key, color] of [['allowed', v('--ok')], ['blocked', v('--bad')]]) {
    if (!series.length) break
    g.beginPath()
    series.forEach((p, i) => i ? g.lineTo(x(i), y(p[key])) : g.moveTo(x(i), y(p[key])))
    g.strokeStyle = color; g.lineWidth = 1.5; g.lineJoin = 'round'; g.stroke()
    g.lineTo(x(series.length - 1), y(0)); g.lineTo(x(0), y(0)); g.closePath()
    g.globalAlpha = .12; g.fillStyle = color; g.fill(); g.globalAlpha = 1
  }
}
addEventListener('resize', draw)

// policy
async function loadPolicy() {
  try {
    $('#policy').value = JSON.stringify(await api('policy'), null, 2)
    msg('#policyMsg', '', '')
  } catch (err) { msg('#policyMsg', err.message, 'bad') }
}
$('#policyLoad').onclick = loadPolicy
$('#policySave').onclick = async () => {
  let body
  try { body = JSON.stringify(JSON.parse($('#policy').value)) } catch (err) { return msg('#policyMsg', 'Invalid JSON: ' + err.message, 'bad') }
  try {
    await api('policy', { method: 'PUT', body })
    msg('#policyMsg', 'Saved. New policy is live.', 'ok')
  } catch (err) { msg('#policyMsg', err.message, 'bad') }
}
function msg(sel, text, cls) { const m = $(sel); m.textContent = text; m.className = 'msg ' + cls }

// try it (demo mode only; demo routes live at the origin root)
const shown = ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset', 'Retry-After']
async function fire(kind) {
  const key = $('#apiKey').value.trim()
  const opts = { method: kind === 'generate' ? 'POST' : 'GET', headers: key ? { 'X-API-Key': key } : {} }
  const url = kind === 'generate' ? '/v1/generate' : '/v1/ping'
  const one = async () => {
    const r = await fetch(url, opts)
    return { r, text: await r.text() }
  }
  const out = $('#tryOut')
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
}
function describe(method, url, r, text) {
  const hdrs = shown.map(k => r.headers.get(k) != null && `${k}: ${r.headers.get(k)}`).filter(Boolean)
  return `${method} ${url} -> ${r.status}\n${hdrs.join('\n')}\n\n${text.slice(0, 600)}`
}
document.querySelectorAll('[data-try]').forEach(b => { b.onclick = () => fire(b.dataset.try) })

token ? start() : show(false)
