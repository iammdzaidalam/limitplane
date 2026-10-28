// Dotted globe on a 2D canvas: rough continents, auto rotation, drag with inertia, hover markers and pings.
// createGlobe(canvas, opts) -> { setMarkers, ping, destroy }. The canvas fills its parent, which holds the tooltip.
// clientGlobe(canvas, opts) adds decision(client, kind, note): a ping at a city picked by a hash of the client id.
(() => {
  // Approximate continent outlines as lng, lat pairs, a few degrees off
  const NORTH_AMERICA = [
    -168, 65.5, -165, 61, -158, 57.5, -153, 58, -145, 60.5, -138, 59, -133, 56.5, -130, 54.5, -127,
    50.5, -124.5, 48.5, -124, 42, -122.5, 37.5, -120, 34.5, -117, 32.5, -115, 30, -112, 26.5, -109.8,
    22.9, -110.5, 24.5, -112.5, 29, -114.5, 31, -109, 26, -106.5, 23, -105.5, 20.5, -102, 18, -96,
    15.5, -92, 14.5, -89, 13, -86, 12, -85, 10, -83, 8.5, -80, 7.5, -77.5, 8, -79, 9.5, -82, 9, -83.5,
    11, -83.5, 15, -86, 16, -88.5, 16, -88, 18.5, -87, 21.5, -90.5, 21, -91, 19, -94, 18.5, -97.5, 21,
    -97.5, 26, -97, 28, -94, 29.5, -90, 29, -89, 30.5, -84.5, 30, -83, 29, -81, 25.5, -80, 26.5, -81,
    31.5, -79, 33.5, -76, 35, -75.5, 38, -74, 40.5, -70, 41.5, -70, 43.5, -67, 45, -64, 45, -61, 46.5,
    -66, 49, -64.5, 50, -59, 52, -56, 53.5, -61, 56, -64.5, 60, -69, 59, -71, 61.5, -78, 62.5, -77.5,
    59, -79, 55, -82, 53, -85, 55.5, -92.5, 57, -94, 59, -94.5, 63, -90, 64, -86, 66.5, -81.5, 67,
    -86, 68.5, -95, 68, -101, 69, -108, 68, -115, 69, -125, 70, -135, 69.5, -141, 70, -152, 70.5,
    -157, 71, -162, 70, -166, 68.5,
  ]

  const ARCTIC_ISLANDS = [
    [-80, 73.5, -74, 72, -67, 69, -62, 66.5, -66, 63, -72, 64, -78, 66, -84, 70, -90, 73],
    [-125, 72, -118, 76, -104, 76, -100, 72, -110, 69, -120, 70],
    [-90, 77, -85, 82, -70, 82.5, -62, 81, -68, 78, -78, 76.5],
  ]

  const GREENLAND = [
    -73, 78.5, -58, 82, -30, 83.5, -20, 81, -18, 76, -22, 70.5, -32, 68, -41, 65, -44, 60, -48, 61,
    -52, 65, -54, 68, -55, 72, -58, 75, -66, 76.5,
  ]

  const SOUTH_AMERICA = [
    -78, 8.5, -77, 7.5, -77.5, 4, -79.5, 1, -80.5, -2, -81.3, -5, -79, -8, -77, -12, -75.5, -15, -71,
    -17.5, -70.5, -20, -70.5, -27, -71.5, -32, -73.5, -37.5, -73.5, -42, -75.5, -48, -74.5, -52, -70,
    -54, -66, -55, -68, -52.5, -65.5, -47, -64.5, -42, -62, -39.5, -57, -38, -58, -34.5, -54, -34,
    -51, -31, -48.5, -27, -47, -24.5, -42.5, -23, -40, -20.5, -39, -16.5, -37, -12, -35, -8.5, -35,
    -5.5, -38, -3.5, -41, -2.5, -44, -2, -48, -1, -50, 0.5, -51, 4, -53, 5.5, -57, 6, -61, 8.5, -63,
    10.5, -68, 11, -71.5, 11, -72.5, 11.5, -75, 10.5, -77, 8.5,
  ]

  const CARIBBEAN = [
    [-85, 22, -80, 23, -74.5, 20.5, -77, 19.8, -84.5, 21.5],
    [-74.5, 18.5, -72, 20, -68.5, 18.5, -71, 17.8, -74, 18.2],
  ]

  const EURASIA = [
    -9.5, 43, -9, 39, -9, 37, -6, 36, -2, 36.7, 0, 38.5, 0.5, 40.5, 3, 42, 3.5, 43.5, 7, 43.5, 9,
    44.3, 10.3, 43.5, 12, 42, 14, 41, 15.7, 38, 16.2, 38.5, 17, 39.5, 18.5, 40, 16, 41.5, 14, 42.5,
    12.5, 44.3, 13.5, 45.5, 14, 45, 15, 44, 16, 43, 19, 42, 19.5, 41, 20, 39.5, 21, 38, 22, 37, 23,
    36.5, 24, 38, 23.5, 40, 25, 40.5, 26, 41.5, 28, 41.5, 28, 43.5, 29.5, 45, 30.5, 46.5, 33, 46, 36,
    45, 37.5, 47, 39, 47.2, 39, 44.5, 41, 42, 41.5, 41.5, 36, 42, 32, 42, 29, 41.2, 27, 40.5, 26.5,
    39, 27, 37, 28, 36.7, 30, 36.5, 33, 36, 36, 36.5, 35, 33, 34.5, 31.5, 33, 31, 32.5, 29.5, 35, 28,
    37, 25, 39, 21.5, 42.5, 16.5, 43.5, 12.7, 45, 13, 49, 14.5, 52, 16.5, 56, 18.5, 59.5, 22.5, 58,
    24, 56.3, 26.3, 54, 24.5, 51, 24.5, 50.5, 26, 48, 28, 48, 30, 50, 30, 52, 27.5, 56.5, 27, 58,
    25.5, 61.5, 25.2, 66, 25.5, 68, 24, 68.5, 23.5, 70, 21, 72.8, 19, 73.5, 16, 75, 12, 77, 8.2, 80,
    12.5, 80.3, 15.5, 82.5, 17, 85, 19.5, 87, 21.5, 89, 22, 90, 22.5, 92, 21.5, 94, 18.5, 97.5, 16.5,
    98, 14, 98.5, 10, 98.5, 8, 100.5, 6, 103.5, 1.5, 104, 2, 103.5, 5, 102, 6.5, 100.5, 13.5, 102,
    12.5, 105, 9, 106.5, 10.5, 109, 12, 109, 15, 106.5, 20.5, 108.5, 21.5, 110.5, 20.5, 113, 22.5,
    117, 23.5, 119.5, 25.5, 121, 28, 122, 30, 120, 34, 119, 35.5, 122.5, 37.5, 119, 37.5, 118, 39,
    121, 40.5, 122, 41, 124, 40, 125, 38, 126.5, 35, 129.5, 35.5, 129.5, 38, 128, 40, 130, 42.5, 133,
    43, 137, 46, 140, 49, 141, 52, 140, 54, 137, 54.5, 143, 59, 150, 59.5, 156, 61, 157, 58, 158, 52,
    156, 51, 161, 57, 163, 60, 170, 60, 178, 63, 180, 65.5, 180, 69, 170, 70, 160, 70, 150, 71.5, 140,
    72.5, 130, 71.5, 128, 73, 113, 73.5, 105, 77.5, 100, 76.5, 88, 75, 82, 73, 75, 72, 73, 73, 69, 73,
    66, 69, 60, 69.5, 55, 68.5, 44, 68.5, 41, 66, 34, 64.5, 38, 66, 33, 69.5, 28, 70.5, 24, 71, 18,
    69.5, 12, 66, 8, 63, 5, 61.5, 5, 59, 7.5, 58, 10.5, 59, 11.5, 57.5, 12.5, 56, 14, 55.5, 16.5, 57,
    19, 59.5, 18, 61, 17.5, 63, 21.5, 64.5, 25, 65.5, 22, 63, 21.5, 61, 23, 60, 26, 60.5, 29, 60, 28,
    59.5, 24, 59.5, 23, 58.5, 21, 57.5, 21, 55.5, 20, 54.5, 18.5, 54.5, 14.5, 54, 12, 54.5, 10, 54.5,
    8.5, 55.5, 8.2, 57.5, 10.5, 57.6, 10.5, 56, 9.8, 55, 8.5, 54, 7, 53.5, 4.5, 52, 3, 51, 1.5, 50.5,
    -1.5, 49.5, -1.5, 48.5, -4.7, 48.5, -4.5, 47.5, -2, 47, -1.2, 46, -1.5, 43.5, -3.5, 43.5, -8,
    43.5,
  ]

  const CHUKOTKA = [-180, 65.5, -172, 65, -170, 66.5, -175, 68, -180, 68.7]

  const EUROPE_ISLANDS = [
    [
      -5.7, 50, -3, 50.5, 1.4, 51, 1.7, 52.5, 0, 53.5, -1.5, 55, -2, 56.5, -3, 58.5, -5, 58.5, -6, 57,
      -5, 55.5, -3, 54.5, -4.5, 52.5, -5.5, 51.7,
    ],
    [-6, 55, -10, 54, -10, 52, -8, 51.5, -6, 52, -5.5, 54.5],
    [-24, 65, -22, 66.3, -15, 66.3, -13.5, 65, -18, 63.5, -22.5, 63.8],
    [52, 71.5, 57, 75, 68, 77, 65, 76, 58, 73, 53, 71],
    [11, 77, 17, 80, 27, 80, 22, 78, 14, 77],
  ]

  const ASIA_ISLANDS = [
    [
      130, 31.5, 131.5, 34, 135, 33.5, 137, 34.5, 140, 35, 141, 38, 141.5, 41, 140, 41.5, 139.5, 38,
      136, 37, 133, 35.5, 130, 33.5,
    ],
    [140, 42, 140.5, 44, 142, 45.5, 145.5, 44.5, 144, 42.5, 142, 41.5],
    [79.7, 8.5, 81.5, 8, 81.8, 6.5, 80, 6, 79.8, 8],
    [120, 22, 121, 25.3, 122, 24.5, 121, 22],
    [120, 18.5, 122, 18.5, 122.5, 14, 121, 13.5, 120, 16],
    [122, 8, 126, 9, 126.5, 6.5, 124, 5.5, 122, 7],
    [95.5, 5.5, 98, 4, 103, 1, 106, -3, 105.5, -5.8, 102, -4, 100, -1, 97, 2],
    [105.5, -6, 108, -6.2, 111, -6.5, 114.5, -7.8, 114, -8.7, 110, -8, 106, -7.3],
    [
      109, 2, 109.5, -1.5, 112, -3.5, 116, -4, 117.5, -1, 119, 1, 118, 5, 117, 7, 115, 4.5, 113, 3,
      110, 1.5,
    ],
    [119, -5.5, 120.5, -2, 123, 1, 125, 1.5, 121, -1, 122.5, -5.5, 120, -5.5],
    [
      131, -1, 134, -1, 137, -2, 141, -2.7, 147, -6, 150, -10.5, 147, -9, 143, -9, 140, -8.5, 138, -8,
      135, -4, 132, -3,
    ],
  ]

  const AFRICA = [
    -6, 35.8, -2, 35.2, 2, 36.8, 10, 37.2, 11, 35, 10, 34, 15, 32.5, 20, 31, 20, 32.5, 25, 31.5, 29,
    31, 32, 31.2, 32.5, 29.5, 34, 28, 35, 24, 37, 21, 38.5, 18, 39.5, 15.5, 42, 12.5, 43.3, 11.5, 45,
    10.5, 51, 11.8, 51, 10, 48, 5, 44, 1, 41, -2, 39.5, -5, 39.5, -8, 40.5, -11, 40.5, -15, 35.5, -20,
    35.5, -24, 33, -26, 32.5, -28.5, 30, -31.5, 27, -33.5, 22, -34.5, 18.5, -34.3, 18, -32, 16.5,
    -28.5, 15, -26, 14.5, -22.5, 12, -17.5, 13.5, -12, 12.5, -6, 9, -1.5, 9.5, 2.5, 8.5, 4.5, 6, 4.3,
    3, 6.3, -2, 5, -5, 5, -8, 4.5, -11, 7, -13.5, 9, -16.5, 12, -17.5, 14.7, -16.5, 18, -16, 21, -17,
    23.5, -14.5, 26, -10, 29, -9.5, 32, -6.5, 34,
  ]

  const MADAGASCAR = [
    49.5, -12, 50.5, -15.5, 48.5, -21, 47, -25, 44, -25, 43.5, -21, 44, -16.5, 47, -14,
  ]

  const AUSTRALIA = [
    114, -22, 114, -26, 115, -33.5, 117, -35, 121, -34, 124, -33, 129, -31.5, 133, -32, 135.5, -34.5,
    137.5, -35.5, 139.5, -37, 143, -38.8, 146.5, -39, 150, -37.5, 151.5, -34, 153, -30, 153.5, -27,
    152, -24, 149.5, -22, 147, -19, 145.5, -16, 145.5, -14.5, 143.5, -11, 142, -11, 141.5, -14, 140,
    -17.5, 136.5, -15.5, 136, -12, 132, -11.5, 130, -12.5, 129, -15, 125, -15, 122, -17.5, 119, -20,
  ]

  const OCEANIA = [
    [145, -41, 148, -41, 148, -43.5, 146, -43.5],
    [
      172.7, -34.5, 174.5, -36.5, 176, -37.5, 178.5, -37.7, 177, -39.5, 175, -41.5, 174.5, -39.5, 173,
      -37,
    ],
    [172.7, -40.5, 174.3, -41.5, 173, -43, 171, -45.5, 168, -46.5, 166.5, -45.5, 170, -43],
  ]

  const ANTARCTIC_PENINSULA = [-65, -62.5, -58, -63.5, -60, -67, -66, -70, -75, -72, -72, -66]

  const RINGS = [
    NORTH_AMERICA,
    ...ARCTIC_ISLANDS,
    GREENLAND,
    SOUTH_AMERICA,
    ...CARIBBEAN,
    EURASIA,
    CHUKOTKA,
    ...EUROPE_ISLANDS,
    ...ASIA_ISLANDS,
    AFRICA,
    MADAGASCAR,
    AUSTRALIA,
    ...OCEANIA,
    ANTARCTIC_PENINSULA,
  ]

  function inside(ring, lng, lat) {
    let hit = false
    const n = ring.length / 2
    for (let i = 0, j = n - 1; i < n; j = i++) {
      const xi = ring[i * 2]
      const yi = ring[i * 2 + 1]
      const xj = ring[j * 2]
      const yj = ring[j * 2 + 1]
      if (yi > lat !== yj > lat && lng < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit
    }
    return hit
  }

  function isLand(lat, lng) {
    if (lat < -70) return true
    for (const ring of RINGS) if (inside(ring, lng, lat)) return true
    return false
  }

  const TAU = Math.PI * 2, DEG = Math.PI / 180, GOLDEN = Math.PI * (3 - Math.sqrt(5))
  const MAX_PITCH = 75 * DEG, FRICTION = 3, BLEND = 4, REST = 0.0004, HOVER_RADIUS = 18, PADDING = 0.06
  const MAX_DT = 1 / 30, PING_MS = 1500, MAX_PINGS = 300
  const DEFAULTS = {
    dotSize: 2.5, dotSpacing: 1.5, rotationSpeed: 6, drag: true, landOpacity: 0.85, oceanOpacity: 0.1,
    backOpacity: 0.12, atmosphere: true, tilt: 18, markerSize: 3.5, maxDpr: 2,
  }

  const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi)
  const unitVec = (lat, lng) => {
    const c = Math.cos(lat * DEG)
    return [c * Math.sin(lng * DEG), Math.sin(lat * DEG), c * Math.cos(lng * DEG)]
  }

  // Fibonacci sphere spreads dots evenly without latitude rings; cached per spacing
  const spheres = new Map()
  function sphere(spacing) {
    if (spheres.has(spacing)) return spheres.get(spacing)
    const total = Math.max(64, Math.round(41253 / (spacing * spacing)))
    const unit = new Float32Array(total * 3), land = new Uint8Array(total)
    for (let i = 0; i < total; i++) {
      const y = 1 - (2 * (i + 0.5)) / total, ring = Math.sqrt(1 - y * y), phi = i * GOLDEN
      const x = ring * Math.sin(phi), z = ring * Math.cos(phi)
      unit[i * 3] = x
      unit[i * 3 + 1] = y
      unit[i * 3 + 2] = z
      land[i] = isLand(Math.asin(y) / DEG, Math.atan2(x, z) / DEG) ? 1 : 0
    }
    const s = { total, unit, land }
    spheres.set(spacing, s)
    return s
  }

  function createGlobe(canvas, opts = {}) {
    const o = { ...DEFAULTS, ...opts }
    const box = canvas.parentElement, ctx = canvas.getContext('2d'), style = getComputedStyle(canvas)
    const { total, unit, land } = sphere(Math.max(1, o.dotSpacing))
    const screen = new Float32Array(total * 3)
    const motion = matchMedia('(prefers-reduced-motion: reduce)'), scheme = matchMedia('(prefers-color-scheme: dark)')
    let marks = [], pings = [], hover = null, drag = null
    let width = 0, height = 0, radius = 0, yaw = 0, pitch = o.tilt * DEG, cosY = 1, sinY = 0, cosP = 1, sinP = 0
    let mode = 'auto', yawV = 0, pitchV = 0, dragYaw = 0, dragPitch = 0, idle = false
    let px = 0, py = 0, pointerOn = false, rect = canvas.getBoundingClientRect()
    let reduced = motion.matches, visible = true, frame = 0, last = 0

    // tooltip: a chip in the text colour with the label knocked out of it
    const tip = document.createElement('span'), tipText = document.createElement('span')
    Object.assign(tip.style, {
      position: 'absolute', zIndex: 1, display: 'none', pointerEvents: 'none', whiteSpace: 'nowrap',
      padding: '4px 8px', borderRadius: '2px', background: 'currentColor', transform: 'translate(-50%, -100%)',
      font: '500 11px/1.4 var(--mono, ui-monospace, monospace)', letterSpacing: '.08em', textTransform: 'uppercase',
    })
    Object.assign(tipText.style, { color: '#fff', mixBlendMode: 'difference' })
    tip.append(tipText)
    if (getComputedStyle(box).position === 'static') box.style.position = 'relative'
    box.append(tip)
    canvas.style.cursor = o.drag ? 'grab' : ''
    canvas.style.touchAction = 'pan-y'

    const toScreen = ([x0, y0, z0]) => {
      const x = x0 * cosY + z0 * sinY, z = z0 * cosY - x0 * sinY
      return [width / 2 + x * radius, height / 2 - (y0 * cosP - z * sinP) * radius, y0 * sinP + z * cosP]
    }

    function project() {
      cosY = Math.cos(yaw); sinY = Math.sin(yaw); cosP = Math.cos(pitch); sinP = Math.sin(pitch)
      const cx = width / 2, cy = height / 2, r = radius
      for (let i = 0; i < total; i++) {
        const x0 = unit[i * 3], y0 = unit[i * 3 + 1], z0 = unit[i * 3 + 2]
        const x = x0 * cosY + z0 * sinY, z = z0 * cosY - x0 * sinY
        screen[i * 3] = cx + x * r
        screen[i * 3 + 1] = cy - (y0 * cosP - z * sinP) * r
        screen[i * 3 + 2] = y0 * sinP + z * cosP
      }
      for (const m of marks) m.s = toScreen(m.v)
    }

    const prune = now => {
      while (pings.length && now - pings[0].t > PING_MS) pings.shift()
      if (pings.length > MAX_PINGS) pings.splice(0, pings.length - MAX_PINGS)
    }

    function tick(dt, now) {
      const auto = hover === null ? o.rotationSpeed * DEG : 0
      if (mode === 'drag') {
        yawV += (dragYaw / Math.max(dt, 0.001) - yawV) * 0.5
        pitchV += (dragPitch / Math.max(dt, 0.001) - pitchV) * 0.5
        dragYaw = dragPitch = 0
      } else if (mode === 'coast') {
        yaw += yawV * dt
        pitch = clamp(pitch + pitchV * dt, -MAX_PITCH, MAX_PITCH)
        const decay = Math.exp(-FRICTION * dt)
        yawV *= decay
        pitchV *= decay
        if (Math.abs(yawV) < Math.abs(auto) + 0.02 && Math.abs(pitchV) < 0.02) mode = 'auto'
      } else {
        yawV += (auto - yawV) * (1 - Math.exp(-BLEND * dt))
        yaw += yawV * dt
      }
      if (yaw > TAU || yaw < -TAU) yaw %= TAU
      prune(now)
      project()
      updateHover()
      idle = mode === 'auto' && auto === 0 && Math.abs(yawV) < REST && !pings.length
    }

    function draw(now) {
      const { dotSize, landOpacity, oceanOpacity, backOpacity, markerSize } = o
      const color = style.color, cx = width / 2, cy = height / 2, r = radius, half = dotSize / 2
      ctx.clearRect(0, 0, width, height)
      ctx.fillStyle = ctx.strokeStyle = color
      if (o.atmosphere) {
        ctx.globalAlpha = 0.28
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.arc(cx, cy, r + 6, 0, TAU)
        ctx.stroke()
        ctx.globalAlpha = 0.04
        ctx.beginPath()
        ctx.arc(cx, cy, r, 0, TAU)
        ctx.fill()
      }
      // back face first, then the front; ocean and land in separate passes for their opacities
      const passes = [[false, 0, oceanOpacity * backOpacity], [false, 1, landOpacity * backOpacity], [true, 0, oceanOpacity], [true, 1, landOpacity]]
      for (const [front, onLand, alpha] of passes) {
        if (alpha <= 0.002) continue
        const size = front ? half : half * 0.7
        ctx.globalAlpha = alpha
        ctx.beginPath()
        for (let i = 0; i < total; i++) {
          if (land[i] !== onLand || screen[i * 3 + 2] > 0 !== front) continue
          const x = screen[i * 3], y = screen[i * 3 + 1]
          ctx.moveTo(x + size, y)
          ctx.arc(x, y, size, 0, TAU)
        }
        ctx.fill()
      }
      marks.forEach(({ s: [x, y, z] }, i) => {
        if (z <= -0.05) return
        const hovered = hover === i, fade = clamp((z + 0.05) / 0.25, 0, 1)
        ctx.globalAlpha = fade
        ctx.beginPath()
        ctx.arc(x, y, markerSize, 0, TAU)
        ctx.fill()
        ctx.globalAlpha = fade * (hovered ? 0.9 : 0.45)
        ctx.lineWidth = hovered ? 1.5 : 1
        ctx.beginPath()
        ctx.arc(x, y, markerSize * (hovered ? 2.6 : 2), 0, TAU)
        ctx.stroke()
      })
      // pings: a dot and a ring that grows and fades, front face only
      ctx.lineWidth = 1.5
      for (const p of pings) {
        const [x, y, z] = toScreen(p.v)
        if (z <= 0) continue
        const k = reduced ? 0 : clamp((now - p.t) / PING_MS, 0, 1)
        ctx.fillStyle = ctx.strokeStyle = p.color
        ctx.globalAlpha = clamp(z / 0.2, 0, 1) * (1 - k)
        ctx.beginPath()
        ctx.arc(x, y, 3, 0, TAU)
        ctx.fill()
        if (k > 0) {
          ctx.beginPath()
          ctx.arc(x, y, 3 + k * 18, 0, TAU)
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1
    }

    function updateHover() {
      let next = null
      if (pointerOn && mode !== 'drag') {
        let best = HOVER_RADIUS * HOVER_RADIUS
        marks.forEach(({ s: [x, y, z] }, i) => {
          const d = (x - px) ** 2 + (y - py) ** 2
          if (z > 0 && d < best) { best = d; next = i }
        })
      }
      hover = next
      showTip()
    }

    function showTip() {
      const m = hover === null ? null : marks[hover]
      const text = m && (typeof m.label === 'function' ? m.label() : m.label)
      if (!text) { tip.style.display = 'none'; return }
      if (tipText.textContent !== text) tipText.textContent = text
      tip.style.color = style.color
      tip.style.display = ''
      const w = tip.offsetWidth, h = tip.offsetHeight
      tip.style.left = clamp(canvas.offsetLeft + m.s[0], w / 2 + 4, box.clientWidth - w / 2 - 4) + 'px'
      tip.style.top = Math.max(h + 4, canvas.offsetTop + m.s[1] - o.markerSize * 3 - 4) + 'px'
    }

    // frame loop: runs while on screen, in a visible tab, without reduced motion, until the globe comes to rest
    const loop = now => {
      frame = 0
      if (!visible || reduced) return
      const dt = last ? Math.min((now - last) / 1000, MAX_DT) : 1 / 60
      last = now
      tick(dt, now)
      draw(now)
      if (!idle) frame = requestAnimationFrame(loop)
      else last = 0
    }
    const start = () => {
      if (frame || !visible || reduced || document.hidden) return
      last = 0
      frame = requestAnimationFrame(loop)
    }
    const stop = () => {
      cancelAnimationFrame(frame)
      frame = last = 0
    }
    const drawStatic = () => {
      project()
      updateHover()
      draw(performance.now())
    }
    const wake = () => (reduced ? drawStatic() : start())

    function resize() {
      rect = canvas.getBoundingClientRect()
      width = Math.round(rect.width)
      height = Math.round(rect.height)
      const dpr = Math.min(devicePixelRatio || 1, o.maxDpr)
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      radius = (Math.min(width, height) / 2) * (1 - PADDING)
      drawStatic()
      start()
    }

    const sizes = new ResizeObserver(resize)
    sizes.observe(box)
    const seen = new IntersectionObserver(([e]) => {
      visible = e ? e.isIntersecting : true
      visible ? wake() : stop()
    })
    seen.observe(box)
    // theme changes repaint even when the globe is at rest
    const theme = new MutationObserver(wake)
    theme.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] })

    const onMotion = e => {
      reduced = e.matches
      if (reduced) { stop(); drawStatic() } else start()
    }
    const onVisibility = () => (document.hidden ? stop() : start())
    const onScroll = () => { rect = canvas.getBoundingClientRect() }
    // hover: the loop picks it up; with reduced motion, redraw only when the hovered marker changes
    const point = () => {
      if (!reduced) return start()
      const before = hover
      updateHover()
      if (hover !== before && visible) draw(performance.now())
    }
    const onPointer = e => {
      px = e.clientX - rect.left
      py = e.clientY - rect.top
      pointerOn = true
      point()
    }
    const onLeave = () => {
      pointerOn = false
      point()
    }
    const onDown = e => {
      if (!o.drag || (e.pointerType === 'mouse' && e.button !== 0)) return
      canvas.setPointerCapture(e.pointerId)
      drag = [e.clientX, e.clientY]
      mode = 'drag'
      yawV = pitchV = dragYaw = dragPitch = 0
      canvas.style.cursor = 'grabbing'
      wake()
    }
    const onMove = e => {
      if (!drag) return
      const s = 1 / Math.max(40, radius), dx = (e.clientX - drag[0]) * s, dy = (e.clientY - drag[1]) * s
      drag = [e.clientX, e.clientY]
      yaw += dx
      pitch = clamp(pitch + dy, -MAX_PITCH, MAX_PITCH)
      dragYaw += dx
      dragPitch += dy
      wake()
    }
    const onUp = () => {
      if (!drag) return
      drag = null
      canvas.style.cursor = 'grab'
      mode = reduced ? 'auto' : 'coast'
      if (reduced) yawV = pitchV = 0
      wake()
    }

    motion.addEventListener('change', onMotion)
    scheme.addEventListener('change', wake)
    document.addEventListener('visibilitychange', onVisibility)
    document.addEventListener('pointerleave', onLeave)
    addEventListener('pointermove', onPointer, { passive: true })
    addEventListener('pointerdown', onPointer, { passive: true })
    addEventListener('blur', onLeave)
    addEventListener('scroll', onScroll, { passive: true, capture: true })
    canvas.addEventListener('pointerdown', onDown)
    canvas.addEventListener('pointermove', onMove)
    for (const t of ['pointerup', 'pointercancel', 'lostpointercapture']) canvas.addEventListener(t, onUp)

    return {
      // markers: [{ lat, lng, label }]; label may be a function, read while the marker is hovered
      setMarkers(list) {
        marks = list.map(m => ({ label: m.label, v: unitVec(m.lat, m.lng), s: [0, 0, -1] }))
        if (hover !== null && hover >= marks.length) hover = null
        project()
        wake()
      },
      ping(lat, lng, color) {
        const now = performance.now()
        pings.push({ v: unitVec(lat, lng), color, t: now })
        prune(now)
        if (visible && !document.hidden) wake()
      },
      destroy() {
        stop()
        sizes.disconnect()
        seen.disconnect()
        theme.disconnect()
        motion.removeEventListener('change', onMotion)
        scheme.removeEventListener('change', wake)
        document.removeEventListener('visibilitychange', onVisibility)
        document.removeEventListener('pointerleave', onLeave)
        removeEventListener('pointermove', onPointer)
        removeEventListener('pointerdown', onPointer)
        removeEventListener('blur', onLeave)
        removeEventListener('scroll', onScroll, { capture: true })
        canvas.removeEventListener('pointerdown', onDown)
        canvas.removeEventListener('pointermove', onMove)
        for (const t of ['pointerup', 'pointercancel', 'lostpointercapture']) canvas.removeEventListener(t, onUp)
        tip.remove()
      },
    }
  }

  // We have no geo data: each client sits near one of these cities, picked by a hash of its id.
  const CITIES = [
    ['London', 51.5, -0.1], ['Frankfurt', 50.1, 8.7], ['Mumbai', 19.1, 72.9], ['Singapore', 1.8, 103.4],
    ['Tokyo', 35.7, 139.7], ['Sydney', -33.9, 151.2], ['São Paulo', -23.5, -46.6], ['New York', 40.7, -74],
    ['San Francisco', 37.8, -122.4], ['Toronto', 43.7, -79.4], ['Johannesburg', -26.2, 28], ['Dubai', 25.2, 55.3],
  ]
  const PING_COLORS = { ok: '#22c55e', warn: '#f59e0b', bad: '#ef4444' }
  // FNV-1a as a fraction in [0, 1), with a final mix so ids that differ in one character spread out
  const hash = s => {
    let x = 2166136261
    for (const c of s) x = Math.imul(x ^ c.codePointAt(0), 16777619)
    x = Math.imul(x ^ (x >>> 16), 0x85ebca6b)
    x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35)
    return ((x ^ (x >>> 16)) >>> 0) / 4294967296
  }

  function place(id) {
    const city = Math.floor(hash(id) * CITIES.length), [, lat, lng] = CITIES[city]
    // a deterministic jitter of up to 2 degrees, retried until it lands on land
    for (let n = 0; n < 8; n++) {
      const la = lat + (hash(id + '#' + n) - 0.5) * 4, lo = lng + (hash(id + '@' + n) - 0.5) * 4
      if (isLand(la, lo)) return { city, lat: la, lng: lo }
    }
    return { city, lat, lng }
  }

  function clientGlobe(canvas, opts) {
    const globe = createGlobe(canvas, opts), style = getComputedStyle(canvas), spots = new Map(), latest = CITIES.map(() => '')
    globe.setMarkers(CITIES.map(([name, lat, lng], i) => ({ lat, lng, label: () => [name, latest[i]].filter(Boolean).join(' · ') })))
    return {
      ...globe,
      // kind is ok, warn or bad, coloured by the page's --ok, --warn and --bad
      decision(client, kind, note) {
        let p = spots.get(client)
        if (!p) {
          if (spots.size > 2000) spots.clear()
          spots.set(client, (p = place(client)))
        }
        latest[p.city] = `${client} · ${note}`
        globe.ping(p.lat, p.lng, style.getPropertyValue('--' + kind).trim() || PING_COLORS[kind])
      },
    }
  }

  Object.assign(window, { createGlobe, clientGlobe })
})()
