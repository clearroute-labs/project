type Grain = { x: number; y: number; life: number; age: number; phase: number; speed: number; tone: number }
export function startDuneGrain(hero: HTMLElement, canvas: HTMLCanvasElement, source: HTMLImageElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let field: Uint8ClampedArray | null = null;
  let width = 1, height = 1, scale = 1, offsetX = 0, offsetY = 0;
  let visible = true, ready = false, frame = 0, last = 0, elapsed = 0;
  let grains: Grain[] = [];
  const fieldWidth = 256, fieldHeight = 144;
  const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
  const smooth = (a: number, b: number, x: number) => {
    const t = clamp((x - a) / (b - a), 0, 1);
    return t * t * (3 - 2 * t);
  };
  const sample = (x: number, y: number) => {
    const i = (clamp(y | 0, 0, fieldHeight - 1) * fieldWidth + clamp(x | 0, 0, fieldWidth - 1)) * 4;
    if (!field) return 0;
    return .2126 * field[i] + .7152 * field[i + 1] + .0722 * field[i + 2];
  };
  const terrain = (x: number, y: number) => {
    // Match the hero's background-size: cover and center bottom positioning.
    const u = (x - offsetX) / (source.naturalWidth * scale);
    const v = (y - offsetY) / (source.naturalHeight * scale);
    if (u < 0 || u > 1 || v < .52 || v > 1) return { mask: 0, slope: 0, depth: 0 };
    const px = u * (fieldWidth - 1), py = v * (fieldHeight - 1);
    const i = ((py | 0) * fieldWidth + (px | 0)) * 4;
    const warm = field ? (field[i] - field[i + 2]) / 255 : .4;
    const mask = smooth(.53, .64, v) * smooth(.13, .3, warm);
    // Follow local dune contours; constrain slope so grains never climb into the sky.
    const gx = field ? sample(px + 2, py) - sample(px - 2, py) : 0;
    const gy = field ? sample(px, py + 2) - sample(px, py - 2) : 0;
    return { mask, slope: clamp(-gx / (Math.abs(gy) + 16), -.55, .55), depth: smooth(.52, 1, v) };
  };
  const reset = (grain: Grain, initial = false) => {
    for (let n = 0; n < 50; n++) {
      grain.x = Math.random() * width;
      grain.y = height * (.45 + Math.random() * .55);
      if (terrain(grain.x, grain.y).mask > .2) break;
    }
    grain.life = 5 + Math.random() * 8;
    grain.age = initial ? Math.random() * grain.life : 0;
    grain.phase = Math.random() * Math.PI * 2;
    grain.speed = .7 + Math.random() * .6;
    grain.tone = (Math.random() * 4) | 0;
  };
  const resize = () => {
    width = hero.clientWidth;
    height = hero.clientHeight;
    const ratio = Math.min(devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    scale = Math.max(width / (source.naturalWidth || 1672), height / (source.naturalHeight || 941));
    offsetX = (width - (source.naturalWidth || 1672) * scale) / 2;
    offsetY = height - (source.naturalHeight || 941) * scale;
    grains = Array.from({ length: Math.min(2200, Math.max(420, Math.round(width * height / 520))) }, () => {
      const g = {} as Grain; reset(g, true); return g;
    });
  };
  const palette = ['rgba(255,226,176,.36)', 'rgba(255,239,208,.45)', 'rgba(124,61,27,.22)', 'rgba(238,188,121,.32)'];
  const draw = (dt: number) => {
    elapsed += dt;
    ctx.clearRect(0, 0, width, height);
    const paths = palette.map(() => new Path2D());
    for (const grain of grains) {
      grain.age += dt;
      const ground = terrain(grain.x, grain.y);
      if (grain.age > grain.life || grain.x > width + 4 || grain.y > height + 4 || ground.mask < .08) {
        reset(grain); continue;
      }
      const x = grain.x * .009, y = grain.y * .016, time = elapsed * .18;
      // A stream function gives coherent curl instead of independent random jitter.
      const curlX = Math.sin(x + time) * Math.cos(y - time * .7);
      const curlY = -Math.cos(x + time) * Math.sin(y - time * .7);
      const wind = (15 + ground.depth * 29) * grain.speed;
      const vx = wind * (1 + .2 * curlX);
      const vy = wind * ground.slope * .52 + curlY * (3 + 8 * ground.depth);
      grain.x += vx * dt;
      grain.y += vy * dt;
      const fade = smooth(0, .7, grain.age) * (1 - smooth(grain.life - 1, grain.life, grain.age));
      const envelope = fade * ground.mask;
      if (envelope < .08) continue;
      // Short rolling hops stay attached to the surface, rather than falling like snow.
      const roll = Math.sin(grain.age * 3.2 + grain.phase);
      const hop = Math.abs(roll) * (1 + 2.5 * ground.depth);
      const length = (.65 + ground.depth * 1.2) * envelope;
      const path = paths[grain.tone];
      path.moveTo(grain.x, grain.y - hop);
      path.lineTo(grain.x - length, grain.y - hop - length * ground.slope * .5);
    }
    ctx.lineCap = 'round';
    ctx.lineWidth = .65;
    for (let i = 0; i < paths.length; i++) {
      ctx.strokeStyle = palette[i];
      ctx.stroke(paths[i]);
    }
  };
  const tick = (now: number) => {
    if (!frame) return;
    // Limit the effect to 30 fps; delta is capped when a tab resumes.
    if (!last || now - last >= 1000 / 30) {
      const dt = last ? Math.min((now - last) / 1000, .06) : 1 / 30;
      last = now;
      draw(dt);
    }
    frame = requestAnimationFrame(tick);
  };
  const sync = () => {
    const active = ready && visible && !document.hidden && !reduced.matches;
    hero.dataset.dustActive = String(active);
    canvas.dataset.state = reduced.matches ? 'reduced-motion' : active ? 'running' : ready ? 'paused' : 'loading';
    if (active && !frame) { last = 0; frame = requestAnimationFrame(tick); }
    if (!active) {
      cancelAnimationFrame(frame); frame = 0; last = 0;
      if (reduced.matches) ctx.clearRect(0, 0, width, height);
    }
  };
  const prepare = () => {
    try {
      const probe = document.createElement('canvas');
      probe.width = fieldWidth; probe.height = fieldHeight;
      const probeContext = probe.getContext('2d', { willReadFrequently: true });
      if (!probeContext) return;
      probeContext.drawImage(source, 0, 0, fieldWidth, fieldHeight);
      field = probeContext.getImageData(0, 0, fieldWidth, fieldHeight).data;
      canvas.dataset.terrain = 'image';
    } catch {
      // The photograph remains usable if cross-origin pixel access is unavailable.
      canvas.dataset.terrain = 'fallback';
    }
    ready = true; resize(); sync();
  };
  const resizeObserver = new ResizeObserver(resize);
  const visibilityObserver = new IntersectionObserver(entries => { visible = entries[0].isIntersecting; sync(); });
  resizeObserver.observe(hero);
  visibilityObserver.observe(hero);
  document.addEventListener('visibilitychange', sync);
  reduced.addEventListener('change', sync);
  if (source.naturalWidth) prepare();
  return () => {
    cancelAnimationFrame(frame); frame = 0;
    resizeObserver.disconnect(); visibilityObserver.disconnect();
    document.removeEventListener('visibilitychange', sync);
    reduced.removeEventListener('change', sync);
    ctx.clearRect(0, 0, width, height);
  };
}
