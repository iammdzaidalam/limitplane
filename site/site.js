const $ = (s, r = document) => r.querySelector(s)
const $$ = (s, r = document) => [...r.querySelectorAll(s)]
const reduce = matchMedia('(prefers-reduced-motion: reduce)')
const us = () => Math.round(performance.now() * 1000)
const fmt = n => n.toLocaleString('en-US')

// numbers come from limitplane.example.json
const TIERS = {
  free: { rate: 5, burst: 10, month: 10000, key: 'demo-free-key', id: 'acme' },
  pro: { rate: 50, burst: 100, month: 1000000, key: 'demo-pro-key', id: 'globex' },
}
const COSTS = { '/healthz': 1, '/v1/embed': 2, '/v1/generate': 5 }
const STORM = { blocks: 20, window: 10e6, ban: 300e6 } // internal/server/server.go, in microseconds
const sec = u => Math.ceil(u / 1e6)

// Same math as gcra() in internal/limiter/rate.go; times are microseconds, tat is the stored int.
function gate(tier, { bans = true, monthly = true } = {}) {
  const c = TIERS[tier], t = 1e6 / c.rate, dvt = c.burst * t
  const g = { c, tat: 0, used: 0, blocks: [], banUntil: 0 }
  g.units = now => Math.min(c.burst, (dvt - Math.max(g.tat - now, 0)) / t)
  g.decide = (path, now) => {
    const cost = COSTS[path] ?? 1
    const deny = (reason, stop, o) => ({ status: 429, reason, stop, cost, ...o })
    if (g.banUntil > now) {
      const retry = sec(g.banUntil - now)
      return deny('banned', 0, { limit: 0, remaining: 0, reset: retry, retry })
    }
    const tat = Math.max(g.tat, now), next = tat + cost * t, allowAt = next - dvt
    if (allowAt > now) {
      g.blocks = g.blocks.filter(b => now - b < STORM.window).concat(now)
      if (bans && g.blocks.length >= STORM.blocks) g.banUntil = now + STORM.ban
      return deny('burst', 3, { limit: c.burst, remaining: Math.floor((dvt - (tat - now)) / t), reset: sec(tat - now), retry: Math.max(1, sec(allowAt - now)) })
    }
    g.tat = next // stored before the monthly check, so a monthly reject still burns burst, as in the gateway
    if (monthly && c.month) {
      if (g.used + cost > c.month) {
        const d = new Date(), retry = Math.ceil((Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) - d) / 1000)
        return deny('monthly', 4, { limit: c.month, remaining: c.month - g.used, reset: retry, retry })
      }
      g.used += cost
    }
    return { status: 200, reason: 'ok', stop: -1, cost, limit: c.burst, remaining: Math.floor((dvt - (next - now)) / t), reset: sec(next - now) }
  }
  return g
}

// cells: n bars, each shows the fraction of its slice that is filled
function cells(el, n) {
  el.style.setProperty('--n', n)
  el.replaceChildren(...Array.from({ length: n }, () => Object.assign(document.createElement('span'), { className: 'cell', innerHTML: '<i></i>' })))
  return v => [...el.children].forEach((c, i) => c.firstChild.style.setProperty('--f', Math.max(0, Math.min(1, v * n - i))))
}

const el = (tag, cls, html) => Object.assign(document.createElement(tag), { className: cls, innerHTML: html })

// globe: a dot sphere; every decision in this tab pings it, placed by a hash of the client id
const globe = (() => {
  const cv = $('#globe'), ctx = cv.getContext('2d'), pts = [], pings = [], N = 1200, GA = Math.PI * (3 - Math.sqrt(5))
  for (let i = 0; i < N; i++) { const y = 1 - 2 * (i + .5) / N, r = Math.sqrt(1 - y * y); pts.push([Math.cos(i * GA) * r, y, Math.sin(i * GA) * r]) }
  const css = getComputedStyle(document.documentElement), C = { ok: css.getPropertyValue('--ok'), warn: css.getPropertyValue('--warn'), bad: css.getPropertyValue('--bad') }
  let rot = 0, tilt = -.35, w = 0, h = 0, dpr = 1, raf = 0, last = 0, drag = null
  const g = { visible: false }
  const proj = ([x, y, z]) => {
    const c = Math.cos(rot), s = Math.sin(rot), X = x * c + z * s, Z = z * c - x * s, ct = Math.cos(tilt), st = Math.sin(tilt)
    return [X, y * ct - Z * st, y * st + Z * ct]
  }
  function draw(now = performance.now()) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h)
    const R = Math.min(w, h) * .42, cx = w / 2, cy = h / 2
    ctx.fillStyle = getComputedStyle(cv).color
    for (const p of pts) {
      const [X, Y, Z] = proj(p)
      ctx.globalAlpha = Z < 0 ? .12 : .3 + .6 * Z
      ctx.fillRect(cx + X * R - .8, cy - Y * R - .8, 1.6, 1.6)
    }
    while (pings.length && !reduce.matches && now - pings[0].t > 2000) pings.shift()
    for (const p of pings) {
      const [X, Y, Z] = proj(p.v), x = cx + X * R, y = cy - Y * R, k = reduce.matches ? 0 : (now - p.t) / 2000
      ctx.globalAlpha = (Z < 0 ? .25 : 1) * (1 - k)
      ctx.fillStyle = ctx.strokeStyle = C[p.c]
      ctx.beginPath(); ctx.arc(x, y, 2.5, 0, 7); ctx.fill()
      if (k) { ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, 3 + k * 16, 0, 7); ctx.stroke() }
    }
    ctx.globalAlpha = 1
  }
  const tick = now => {
    raf = 0
    if (!drag && !reduce.matches) rot += Math.min(now - last, 50) * .00012
    last = now; draw(now)
    if (g.visible && !document.hidden && !reduce.matches) raf = requestAnimationFrame(tick)
  }
  const start = () => { if (!raf && g.visible) { last = performance.now(); raf = requestAnimationFrame(tick) } }
  const size = () => { dpr = Math.min(devicePixelRatio || 1, 2); w = cv.clientWidth; h = cv.clientHeight; cv.width = w * dpr; cv.height = h * dpr; draw() }
  new ResizeObserver(size).observe(cv)
  new IntersectionObserver(es => { g.visible = es[0].isIntersecting; start() }).observe(cv)
  document.addEventListener('visibilitychange', start)
  reduce.addEventListener('change', start)
  cv.onpointerdown = e => { drag = [e.clientX, e.clientY]; cv.setPointerCapture(e.pointerId) }
  cv.onpointermove = e => {
    if (!drag) return
    rot += (e.clientX - drag[0]) * .008; tilt = Math.max(-1.2, Math.min(1.2, tilt + (e.clientY - drag[1]) * .005))
    drag = [e.clientX, e.clientY]; draw()
  }
  cv.onpointerup = cv.onpointercancel = () => { drag = null }
  g.ping = (id, c) => {
    let a = 2166136261, b = 0
    for (const ch of id) { a = Math.imul(a ^ ch.charCodeAt(0), 16777619); b = Math.imul(b ^ a, 2246822507) + 1 }
    const lat = Math.asin(2 * ((a >>> 0) / 2 ** 32) - 1), lon = 2 * Math.PI * ((b >>> 0) / 2 ** 32)
    pings.push({ v: [Math.cos(lat) * Math.cos(lon), Math.sin(lat), Math.cos(lat) * Math.sin(lon)], c, t: performance.now() })
    if (pings.length > 60) pings.shift()
    if (reduce.matches && g.visible) draw(); else start()
  }
  return g
})()

let decisions = 0
function emit(id, r) {
  $('#count').textContent = fmt(++decisions)
  globe.ping(id, r.status === 200 ? 'ok' : r.reason === 'burst' ? 'warn' : 'bad')
}

// anonymous clients (documentation IPs) on the free tier; three of them send too many AI calls
{
  const H = '/healthz', E = '/v1/embed', G = '/v1/generate'
  const anon = Array.from({ length: 24 }, (_, i) => ({ id: `203.0.113.${(i * 37 + 11) % 254 + 1}`, g: gate('free'), p: [.7, .3, .3][i] ?? .05, paths: i < 3 ? [G] : [H, H, E, G] }))
  setInterval(() => {
    if (!globe.visible || document.hidden) return
    for (const c of anon) if (Math.random() < c.p) emit(c.id, c.g.decide(c.paths[Math.random() * c.paths.length | 0], us()))
  }, 200)
}

// clock
{
  const tick = () => { $('#clock').textContent = new Date().toISOString().slice(11, 19) + ' UTC' }
  tick(); setInterval(tick, 1000)
}

// hero wordmark: sized to span the width, revealed in horizontal slices
{
  const wm = $('#wm'), h1 = wm.parentElement, B = 4
  if (!reduce.matches) {
    for (let i = 1; i < B; i++) wm.append(wm.firstElementChild.cloneNode(true))
    ;[...wm.children].forEach((s, i) => {
      s.style.clipPath = `inset(calc(${i * 100 / B}% - 1px) 0 calc(${100 - (i + 1) * 100 / B}% - 1px) 0)`
      s.style.setProperty('--i', i); s.style.setProperty('--x', (i % 2 ? .3 : -.3) + 'em')
    })
  }
  const fit = () => { h1.style.fontSize = '100px'; h1.style.fontSize = 100 * h1.clientWidth / wm.offsetWidth + 'px' }
  fit(); document.fonts?.ready.then(fit); addEventListener('resize', fit)
}

// hero: simulated traffic against the free tier
{
  const H = '/healthz', E = '/v1/embed', G = '/v1/generate', SEQ = [H, G, G, H, G, E, G, H, H, G, G, E]
  const g = gate('free', { bans: false, monthly: false }), set = cells($('#live-cells'), 10)
  const log = $('#live-log'), num = $('#live-n'), btn = $('#live-toggle')
  let i = 0, timer
  const step = (now = us()) => {
    const path = SEQ[i++ % SEQ.length], r = g.decide(path, now), post = path !== H
    emit(g.c.id, r)
    log.prepend(el('li', '', `<span class="code ${r.status === 200 ? 'ok' : 'no'}">${r.status}</span><span class="p">${post ? 'POST' : 'GET'} ${path}</span><span class="${r.status === 200 ? '' : 'no'}">${r.status === 200 ? '-' + r.cost : 'burst'}</span>`))
    while (log.children.length > 5) log.lastChild.remove()
  }
  const paint = () => { const u = g.units(us()); set(u / 10); num.textContent = Math.floor(u) }
  for (let k = 7; k > 0; k--) step(us() - k * 450000)
  paint()
  const run = on => {
    clearInterval(timer); timer = on && setInterval(() => { step(); paint() }, 450)
    btn.textContent = on ? 'Pause' : 'Resume'; btn.setAttribute('aria-pressed', !on)
  }
  setInterval(() => timer && paint(), 100) // between steps the bucket refills
  btn.onclick = () => run(!timer)
  run(!reduce.matches)
  reduce.onchange = e => run(!e.matches)
}

// playground
{
  let g, setBurst
  const setMonth = cells($('#month-cells'), 1)
  const $o = id => document.getElementById(id), chips = $o('chips'), status = $o('status'), out = $o('out'), trace = $o('trace')
  const STAGES = ['ban', 'who', 'cost', 'burst', 'monthly', 'respond']
  const msg = (r, tier) => ({
    burst: `Too many requests for the ${tier} tier (this route costs ${r.cost} units). Retry in ${r.retry}s.`,
    monthly: `The ${tier} plan's monthly quota of ${r.limit} units is used up. It resets on the 1st (UTC).`,
    banned: `This client is temporarily blocked for abusive traffic. Retry in ${r.retry}s.`,
  })[r.reason]

  function reset(tier = g?.tierName || 'free', note = 'Reset. Send a request to see the response.') {
    g = gate(tier); g.tierName = tier
    const c = g.c, per = c.burst > 20 ? c.burst / 20 : 1
    setBurst = cells($o('burst-cells'), c.burst / per)
    $o('burst-note').textContent = per > 1 ? `(1 cell = ${per} units)` : `(refills ${c.rate}/s)`
    $o('tier-note').textContent = `${tier}: ${c.rate} units/s, burst ${c.burst}, ${fmt(c.month)} units a month`
    chips.replaceChildren(el('li', 'muted', 'none yet'))
    status.textContent = note; status.className = 'status'
    paint()
  }

  function paint() {
    const now = us(), c = g.c, u = g.units(now)
    setBurst(u / c.burst)
    $o('burst-n').textContent = `${Math.floor(u)} / ${c.burst}`
    setMonth((c.month - g.used) / c.month)
    $o('month-n').textContent = `${fmt(c.month - g.used)} / ${fmt(c.month)}`
    const ban = $o('ban'), left = g.banUntil - now
    ban.hidden = left <= 0
    if (left > 0) ban.textContent = `Autopilot ban: this client is blocked for ${sec(left)}s`
  }

  function show(method, path, r) {
    const tier = g.tierName, ok = r.status === 200
    const text = [`HTTP/1.1 ${r.status} ${ok ? 'OK' : 'Too Many Requests'}`, `RateLimit-Limit: ${r.limit}`, `RateLimit-Remaining: ${r.remaining}`, `RateLimit-Reset: ${r.reset}`]
    if (ok) text.push('', '(request goes on to your upstream)')
    else text.push(`Retry-After: ${r.retry}`, 'Content-Type: application/json', '', JSON.stringify({ error: 'rate_limited', reason: r.reason, retryAfter: r.retry, message: msg(r, tier) }))
    out.textContent = [`${method} ${path}  X-Api-Key: ${g.c.key}`, ...text].join('\n')
    trace.replaceChildren(...STAGES.map((s, i) => {
      const st = i === 5 || r.stop < 0 || i < r.stop ? 'pass' : i === r.stop ? 'stop' : ''
      const li = el('li', '', s)
      li.dataset.s = st
      return li
    }))
    status.textContent = ok ? `200 allowed, ${r.remaining} units left in the bucket` : `429 ${r.reason}, Retry-After ${r.retry}s`
    status.className = 'status ' + (ok ? 'ok' : 'no')
  }

  function send(method, path) {
    const r = g.decide(path, us())
    emit(g.c.id, r)
    if (chips.firstChild.classList.contains('muted')) chips.replaceChildren()
    chips.prepend(el('li', '', `<b class="${r.status === 200 ? 'ok' : 'no'}">${r.status}</b>${path}<span class="muted">${r.status === 200 ? '-' + r.cost : r.reason}</span>`))
    while (chips.children.length > 14) chips.lastChild.remove()
    paint()
    return r
  }

  $$('[data-send]').forEach(b => b.onclick = () => {
    const [m, p] = b.dataset.send.split(' ')
    show(m, p, send(m, p))
  })
  $o('flood').onclick = () => {
    const rs = Array.from({ length: 30 }, () => send('POST', '/v1/generate'))
    show('POST', '/v1/generate', rs.at(-1))
    const ok = rs.filter(r => r.status === 200).length, by = k => rs.filter(r => r.reason === k).length
    status.textContent = `Flood: ${ok} allowed, ${by('burst')} blocked by burst, ${by('banned')} banned` + (g.banUntil ? '. Autopilot banned this client for 5 minutes.' : '')
    status.className = 'status ' + (ok === 30 ? 'ok' : 'no')
  }
  $o('month').onclick = () => {
    g.used = g.c.month - 8
    paint()
    status.textContent = '8 units left this month. Two AI calls will not fit.'
    status.className = 'status'
  }
  $o('reset').onclick = () => reset()
  $$('[name=tier]').forEach(r => r.onchange = () => reset(r.value))
  $$('[data-tier]').forEach(a => a.addEventListener('click', () => { const r = $o('tier-' + a.dataset.tier); r.checked = true; r.onchange() }))
  reset('free', 'Example response shown. Send a request to see yours.')
  setInterval(paint, 100)
}

// pipeline
{
  const tiles = $$('#pipe .stage'), btns = $$('.scen button'), outcome = $('#outcome')
  const TEXT = {
    '-1': 'Every check passed. The request goes upstream with RateLimit-Limit, -Remaining and -Reset on the response.',
    3: '429 with reason burst and a Retry-After. The burst bucket was empty, and the monthly plan is not charged.',
    4: '429 with reason monthly. The plan is used up, and Retry-After runs to the 1st of next month (UTC).',
    0: '429 with reason banned. Autopilot banned this client after repeated burst blocks, so nothing else runs.',
  }
  let seq = 0
  function play(stop, animate = true) {
    const id = ++seq
    btns.forEach(b => b.setAttribute('aria-pressed', b.dataset.stop == stop))
    tiles.forEach(t => t.removeAttribute('data-s'))
    tiles.forEach((t, i) => {
      const s = i === 5 || stop < 0 || i < stop ? 'pass' : i === stop ? 'stop' : 'skip'
      const at = 420 * (stop < 0 ? i : Math.min(i, stop + 1))
      if (!animate || reduce.matches) t.dataset.s = s
      else setTimeout(() => id === seq && (t.dataset.s = s), at)
    })
    outcome.textContent = TEXT[stop]
  }
  btns.forEach(b => b.onclick = () => play(+b.dataset.stop))
  play(-1, false)
  new IntersectionObserver((es, o) => es[0].isIntersecting && (o.disconnect(), seq === 1 && play(-1)), { threshold: .5 }).observe($('#pipe'))
}

// quickstart tabs
{
  const tabs = $$('[role=tab]')
  const pick = i => tabs.forEach((t, j) => {
    t.setAttribute('aria-selected', i === j); t.tabIndex = i === j ? 0 : -1
    document.getElementById(t.getAttribute('aria-controls')).hidden = i !== j
  })
  tabs.forEach((t, i) => {
    t.onclick = () => pick(i)
    t.onkeydown = e => {
      const to = { ArrowDown: i + 1, ArrowRight: i + 1, ArrowUp: i - 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key]
      if (to == null) return
      e.preventDefault(); const n = (to + tabs.length) % tabs.length; pick(n); tabs[n].focus()
    }
  })
}

// copy, theme
const CHECK = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>'
async function copy(text) {
  try { await navigator.clipboard.writeText(text); $('#toast').textContent = 'Copied to clipboard'; return true }
  catch { $('#toast').textContent = 'Select the text and copy it'; return false }
}
$$('[data-copy]').forEach(b => b.onclick = async () => {
  const html = b.innerHTML, ok = await copy(document.getElementById(b.dataset.copy).textContent)
  b.innerHTML = b.classList.contains('icon') ? (ok ? CHECK : '!') : ok ? 'Copied' : 'Press Ctrl+C'
  setTimeout(() => { b.innerHTML = html }, 1500)
})
function toggleTheme() {
  const root = document.documentElement
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches
  root.dataset.theme = dark ? 'light' : 'dark'
  try { localStorage.setItem('lp-theme', root.dataset.theme) } catch {}
}
$('#theme').onclick = toggleTheme

// command palette: jump to sections, run a few actions
{
  const dlg = $('#pal'), q = $('#pal-q'), list = $('#pal-list')
  const jump = id => () => document.getElementById(id).scrollIntoView({ behavior: reduce.matches ? 'auto' : 'smooth' })
  const ITEMS = [['Playground', 'play'], ['Pipeline', 'how'], ['Quickstart', 'start'], ['Policy file', 'policy'], ['Plans', 'plans'], ['Under the hood', 'under'], ['Benchmarks', 'bench']]
    .map(([t, id]) => ({ g: 'Sections', t, hint: '#' + id, run: jump(id) }))
    .concat([
      { g: 'Actions', t: 'Toggle theme', hint: '', run: toggleTheme },
      { g: 'Actions', t: 'Copy install command', hint: 'go install', run: () => copy($('#install').textContent) },
      { g: 'Actions', t: 'Open the source on GitHub', hint: '↗', run: () => { location.href = 'https://github.com/iammdzaidalam/limitplane' } },
    ])
  let shown = [], sel = 0, back
  function render() {
    const term = q.value.trim().toLowerCase()
    shown = ITEMS.filter(it => it.t.toLowerCase().includes(term))
    sel = Math.max(0, Math.min(sel, shown.length - 1))
    const rows = []
    shown.forEach((it, i) => {
      if (it.g !== shown[i - 1]?.g) { const g = el('li', 'grp', it.g); g.setAttribute('role', 'presentation'); rows.push(g) }
      const li = el('li', '', `${it.t}<span>${it.hint}</span>`)
      li.setAttribute('role', 'option')
      Object.assign(li, { id: 'pal-o' + i, onclick: () => run(i), onmousemove: () => { if (sel !== i) { sel = i; render() } } })
      li.setAttribute('aria-selected', i === sel)
      rows.push(li)
    })
    list.replaceChildren(...(rows.length ? rows : [el('li', 'empty', 'No matches')]))
    q.setAttribute('aria-activedescendant', shown.length ? 'pal-o' + sel : '')
    $('#pal-o' + sel)?.scrollIntoView({ block: 'nearest' })
  }
  function run(i) { const it = shown[i]; if (!it) return; dlg.close(); it.run() }
  function open() { back = document.activeElement; q.value = ''; sel = 0; render(); dlg.showModal(); q.focus() }
  q.oninput = () => { sel = 0; render() }
  q.onkeydown = e => {
    const d = { ArrowDown: 1, ArrowUp: -1 }[e.key]
    if (d) { e.preventDefault(); sel = (sel + d + shown.length) % (shown.length || 1); render() }
    else if (e.key === 'Enter') { e.preventDefault(); run(sel) }
  }
  dlg.onclick = e => { if (e.target === dlg) dlg.close() }
  dlg.onclose = () => back?.focus({ preventScroll: true })
  $('#pal-open').onclick = open
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); dlg.open ? dlg.close() : open() }
  })
}

// footer mark: route costs as bars against the limit line
$('#mark').replaceChildren(...[1, 2, 1, 1, 5, 1, 2, 1, 5, 1, 1, 2, 5, 1, 1, 5, 2, 1, 1, 5, 1, 2, 1, 5, 1, 1, 2, 5].map(c => {
  const h = c * 20, i = document.createElement('i')
  i.style.cssText = `--h:${h};--x:${Math.max(0, (h - 60) / h * 100)}`
  return i
}))

// entrance: stagger siblings, once
{
  const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && (e.target.classList.add('in'), io.unobserve(e.target))), { threshold: .12 })
  $$('.rv').forEach((e, i) => { e.style.setProperty('--d', (i % 4) * 70 + 'ms'); io.observe(e) })
  $$('.bars').forEach(b => io.observe(b))
}
