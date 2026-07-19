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

  // Mobile sidebar toggle
  const toggle = document.getElementById("navToggle");
  const closeBtn = document.getElementById("navClose");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");

  function openNav() {
    sidebar.classList.add("open");
    toggle.classList.add("open");
    overlay.classList.add("show");
    document.body.classList.add("nav-open");
    toggle.setAttribute("aria-expanded", "true");
  }
  function closeNav() {
    sidebar.classList.remove("open");
    toggle.classList.remove("open");
    overlay.classList.remove("show");
    document.body.classList.remove("nav-open");
    toggle.setAttribute("aria-expanded", "false");
  }

  if (toggle && sidebar && overlay) {
    toggle.addEventListener("click", openNav);
    if (closeBtn) closeBtn.addEventListener("click", closeNav);
    overlay.addEventListener("click", closeNav);
    sidebar.querySelectorAll(".nav-item").forEach((item) =>
      item.addEventListener("click", closeNav)
    );
  }
});
