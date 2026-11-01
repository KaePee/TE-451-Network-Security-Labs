// Countdown display only. The server enforces the deadline on every submit,
// so changing this clock (or the laptop's) changes nothing.
(function () {
  const el = document.getElementById("lab-timer");
  if (!el) return;
  let left = parseInt(el.dataset.seconds, 10);
  const started = Date.now();
  const out = el.querySelector("[data-left]");

  function fmt(s) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    const pad = (n) => String(n).padStart(2, "0");
    return (h ? h + ":" : "") + pad(m) + ":" + pad(sec);
  }

  function tick() {
    const now = Math.max(0, left - Math.floor((Date.now() - started) / 1000));
    out.textContent = fmt(now);
    el.classList.toggle("urgent", now <= 300);
    if (now === 0) {
      // Reload so the page shows the server's view (Time up).
      setTimeout(() => window.location.reload(), 1500);
      return;
    }
    setTimeout(tick, 1000);
  }
  tick();
})();
