/* Radial gauge — signature element halaman Cek URL.
   Menggambar setengah lingkaran 0-100, warna berubah teal -> kuning -> merah. */

function drawGauge(canvasId, value) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h - 10, radius = 100;

  ctx.clearRect(0, 0, w, h);

  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, radius, startAngle, endAngle);
  ctx.lineWidth = 16;
  ctx.strokeStyle = "#1C2740";
  ctx.lineCap = "round";
  ctx.stroke();

  // Value arc
  const pct = Math.max(0, Math.min(100, value)) / 100;
  const valueAngle = startAngle + pct * Math.PI;

  let color;
  if (value < 35) color = "#35C79A";
  else if (value < 65) color = "#F0A93B";
  else color = "#FF5D5D";

  ctx.beginPath();
  ctx.arc(cx, cy, radius, startAngle, valueAngle);
  ctx.lineWidth = 16;
  ctx.strokeStyle = color;
  ctx.lineCap = "round";
  ctx.stroke();

  // Needle-less tick marks at 0, 50, 100
  ctx.font = "11px 'JetBrains Mono', monospace";
  ctx.fillStyle = "#5A6684";
  ctx.textAlign = "left";
  ctx.fillText("0", cx - radius - 8, cy + 4);
  ctx.textAlign = "right";
  ctx.fillText("100", cx + radius + 8, cy + 4);

  return color;
}
