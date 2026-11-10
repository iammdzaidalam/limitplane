// AI panel: "Explain" for a decision, client or tenant, and an ops chat over incident memory.
// Loaded after app.js and uses its helpers ($, h, api, orgQ, toast, clock). Every answer has a rule-based
// part that needs no model; a model's rewrite is shown on top when the server has one.
(() => {
  const root = $('#ai')
  if (!root) return
  const tz = () => String(-new Date().getTimezoneOffset())
  let status = null, drawerD = null

  // [F2] / [M4, F1] become chips whose title is the fact they cite.
  function cited(text, lookup) {
    const out = [], re = /\[([A-Z]\d+(?:\s*,\s*[A-Z]\d+)*)\]/g
    let at = 0, m
    while ((m = re.exec(text))) {
      out.push(text.slice(at, m.index))
      for (const id of m[1].split(/\s*,\s*/)) out.push(h('abbr', { className: 'cite', tabIndex: 0, title: lookup[id] || id }, id))
      at = m.index + m[0].length
    }
    out.push(text.slice(at))
    return out
  }

  function narrative(n, lookup) {
    if (n?.text) return h('p', { className: 'ai-a' }, ...cited(n.text, lookup), h('span', { className: 'by' }, 'written by ' + n.model + ' from the facts below'))
    if (n?.fallback) return h('p', { className: 'by' }, `${n.model} answer not used (${n.fallback}); showing the rule-based reading.`)
    return null
  }

  function points(title, ps, lookup) {
    if (!ps?.length) return null
    return h('div', {}, h('h3', {}, title), h('ul', {}, ...ps.map(p => h('li', {}, p.text, ...(p.facts || []).map(id => h('abbr', { className: 'cite', tabIndex: 0, title: lookup[id] || id }, id))))))
  }

  function explanation(e) {
    const lookup = Object.fromEntries((e.facts || []).map(f => [f.id, f.text]))
    return h('div', { className: 'ai-ex' },
      narrative(e.narrative, lookup),
      h('p', { className: 'why' }, e.summary),
      points('Findings', (e.findings || []).slice(1), lookup),
      points('What to do', e.actions, lookup),
      e.facts?.length ? h('details', {}, h('summary', { className: 'micro' }, `Facts (${e.facts.length})`),
        h('dl', { className: 'kv cv' }, ...e.facts.map(f => h('div', {}, h('dt', {}, f.id + ' · ' + f.kind), h('dd', {}, f.text))))) : null)
  }

  async function explain(body, into) {
    into.replaceChildren(h('p', { className: 'meta' }, status?.model ? 'Explaining, then asking ' + status.model + '…' : 'Explaining…'))
    try { into.replaceChildren(explanation(await api(orgQ('ai/explain'), { method: 'POST', body: JSON.stringify(body) }))) }
    catch (err) { into.replaceChildren(h('p', { className: 'msg bad' }, "Couldn't explain: " + err.message)) }
  }

  // layout
  const log = h('div', { className: 'ai-log', role: 'log', 'aria-live': 'polite' })
  const q = h('input', { id: 'aiQ', placeholder: 'What happened to acme last night?', autocomplete: 'off', spellcheck: false, maxLength: 500 })
  const mode = h('span', { className: 'micro' })
  const form = h('form', { className: 'cmd ai-cmd' }, h('div', { className: 'cpill' }, h('label', { htmlFor: 'aiQ', className: 'sr' }, 'Ask about incidents'), q), h('button', { className: 'btn primary', type: 'submit' }, 'Ask'))
  const target = h('input', { id: 'aiT', placeholder: 'Client IP or tenant id', autocomplete: 'off', spellcheck: false })
  const exOut = h('div', {}, h('p', { className: 'meta' }, 'Pick a client or tenant, or use Explain on a decision or a client card.'))
  const incidents = h('div', { className: 'rows cv' })
  root.replaceChildren(
    h('section', { className: 'card c7', 'aria-labelledby': 'h-chat' },
      h('div', { className: 'ch' }, h('h2', { id: 'h-chat' }, 'Ask the gateway'), h('span', { className: 'spacer' }), mode),
      h('p', { className: 'meta' }, 'Answers come from remembered incidents (bans, storms, quota alerts, outages, policy reloads) and live state, with citations.'),
      log, form),
    h('section', { className: 'card c5', 'aria-labelledby': 'h-explain' },
      h('div', { className: 'ch' }, h('h2', { id: 'h-explain' }, 'Explain')),
      h('form', { className: 'cmd ai-cmd', onsubmit: e => { e.preventDefault(); const v = target.value.trim(); if (v) explain(/^[0-9a-f.:/]+$/i.test(v) && /[.:]/.test(v) ? { client: v } : { tenant: v }, exOut) } },
        h('div', { className: 'cpill' }, h('label', { htmlFor: 'aiT', className: 'sr' }, 'Client or tenant'), target), h('button', { className: 'btn', type: 'submit' }, 'Explain')),
      exOut,
      h('div', { className: 'ch' }, h('h2', {}, 'Incidents'), h('span', { className: 'spacer' }), h('button', { className: 'btn small', type: 'button', onclick: () => loadIncidents() }, 'Refresh')),
      incidents))

  form.onsubmit = async e => {
    e.preventDefault()
    const question = q.value.trim()
    if (!question) return
    q.value = ''
    log.append(h('p', { className: 'ai-q' }, question))
    const a = h('div', {}, h('p', { className: 'meta' }, 'Searching memory…'))
    log.append(a)
    a.scrollIntoView({ block: 'nearest' })
    try {
      const r = await api(orgQ('ai/chat'), { method: 'POST', body: JSON.stringify({ question, tz: tz() }) })
      const lookup = Object.fromEntries([...(r.hits || []).map(x => [x.ref, `${clock(x.time)} ${x.kind}: ${x.text}`]), ...(r.facts || []).map(f => [f.id, f.text])])
      const rules = h('p', { className: 'ai-a' }, ...cited(r.answer, lookup)), n = narrative(r.narrative, lookup)
      a.replaceChildren(...(r.narrative?.text ? [n, h('details', {}, h('summary', { className: 'micro' }, 'Rule-based answer'), rules)] : [rules, n]).filter(Boolean))
    } catch (err) { a.replaceChildren(h('p', { className: 'msg bad' }, "Couldn't answer: " + err.message)) }
    a.scrollIntoView({ block: 'nearest' })
  }

  async function loadIncidents() {
    try {
      const hits = await api(orgQ('ai/incidents?tz=' + tz()))
      incidents.replaceChildren(...(hits.length ? hits.slice(0, 12).map(x => h('div', { className: 'r' },
        h('div', {}, h('span', { className: 'pill ' + ({ ban: 'warn', storm: 'bad', degraded: 'bad', quota: 'warn' }[x.kind] || '') }, x.kind), ' ', h('span', { className: 'sub2' }, clock(x.time) + (x.tenant ? ' · ' + x.tenant : '')),
          h('span', { className: 'sub2' }, x.text), x.note ? h('span', { className: 'sub2' }, x.note + (x.noteBy && x.noteBy !== 'rules' ? ` (${x.noteBy})` : '')) : null))) : [h('div', { className: 'state-row' }, 'Nothing notable yet.')]))
    } catch (err) { incidents.replaceChildren(h('div', { className: 'state-row bad' }, "Couldn't load incidents: " + err.message)) }
  }

  async function loadStatus() {
    try {
      status = await api('ai/status')
      mode.textContent = status.model ? status.model + (status.shareIPs ? ' · sees IPs' : ' · IPs hashed') : 'rules only, no model'
      mode.title = 'Model calls: ' + status.calls
    } catch {}
  }

  // inspector: an Explain button under the decision
  const dOut = $('#dAI'), dBtn = $('#dExplain')
  if (dBtn) dBtn.onclick = () => drawerD && explain({ decision: Object.fromEntries(Object.entries(drawerD).filter(([k]) => k[0] !== '_')) }, dOut)

  window.lpAI = {
    // app.js calls these: openDrawer -> decision(d), a client card's Explain -> client(id), connect -> listen(es)
    decision(d) { drawerD = d; dOut?.replaceChildren() },
    client(id) { location.hash = '#/ask'; target.value = id; explain({ client: id }, exOut) },
    tenant(id) { location.hash = '#/ask'; target.value = id; explain({ tenant: id }, exOut) },
    listen(es) {
      loadStatus(); loadIncidents()
      es.addEventListener('incident', loadIncidents)
      es.addEventListener('note', e => {
        const n = JSON.parse(e.data)
        toast(`Incident note for ${n.client || n.tenant}: ${n.note}`, 'warn')
        loadIncidents()
      })
    },
  }
})()
