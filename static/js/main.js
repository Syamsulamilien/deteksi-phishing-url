// Tab switcher (dipakai di halaman Dokumentasi)
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      const group = btn.closest(".tabs");
      const panelId = btn.dataset.tab;
      group.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const panelsWrap = group.parentElement;
      panelsWrap.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      document.getElementById(panelId).classList.add("active");
    });
  });
});
