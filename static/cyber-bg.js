// MalSense cyber theme - animated "network" background (pink + cyan nodes joined by thin lines).
// Purely decorative: drawn on a canvas behind the page, never blocks clicks.
(function () {
  const canvas = document.getElementById("cyber-bg");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const COLORS = ["255,47,214", "29,233,255"];          // pink, cyan
  const LINK = 120;                                     // max distance (px) for a connecting line
  let w, h, dots = [];

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + "px"; canvas.style.height = h + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = Math.min(90, Math.round((w * h) / 16000));  // fewer dots on small screens
    dots = Array.from({ length: n }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25,
      r: Math.random() * 1.4 + .8, c: COLORS[Math.random() < .5 ? 0 : 1]
    }));
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < dots.length; i++) {
      const a = dots[i];
      for (let j = i + 1; j < dots.length; j++) {
        const b = dots[j], dx = a.x - b.x, dy = a.y - b.y, d = Math.hypot(dx, dy);
        if (d < LINK) {
          ctx.strokeStyle = `rgba(${a.c},${(1 - d / LINK) * .22})`;
          ctx.lineWidth = .6;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    for (const p of dots) {
      ctx.fillStyle = `rgba(${p.c},.85)`;
      ctx.shadowColor = `rgba(${p.c},.9)`; ctx.shadowBlur = 6;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      if (!still) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }
    }
    if (!still) requestAnimationFrame(draw);
  }

  window.addEventListener("resize", () => { resize(); if (still) draw(); });
  resize(); draw();
})();
