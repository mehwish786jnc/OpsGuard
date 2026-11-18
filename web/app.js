/* OpsGuard "Dark Tech" landing — interactions. Vanilla JS, no dependencies. */
(function () {
  "use strict";

  /* ---------------------------------------------------- Mobile full-screen menu */
  var burger = document.getElementById("burger");
  var menu = document.getElementById("mobileMenu");
  var close = document.getElementById("menuClose");

  function openMenu() {
    if (!menu) return;
    menu.hidden = false;
    document.body.style.overflow = "hidden";
    if (burger) burger.setAttribute("aria-expanded", "true");
  }
  function closeMenu() {
    if (!menu) return;
    menu.hidden = true;
    document.body.style.overflow = "";
    if (burger) burger.setAttribute("aria-expanded", "false");
  }
  if (burger) burger.addEventListener("click", openMenu);
  if (close) close.addEventListener("click", closeMenu);
  if (menu) {
    menu.addEventListener("click", function (e) {
      if (e.target.tagName === "A") closeMenu();
    });
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && menu && !menu.hidden) closeMenu();
  });

  /* ------------------------------------------------------------- Copy install */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  }

  document.querySelectorAll(".install").forEach(function (box) {
    var btn = box.querySelector(".install__btn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      copyText(box.getAttribute("data-copy") || "").then(function () {
        box.classList.add("is-copied");
        setTimeout(function () {
          box.classList.remove("is-copied");
        }, 1600);
      });
    });
  });

  /* --------------------------------------------------------- Reveal on scroll */
  var revealEls = document.querySelectorAll(
    ".section-title, .trace, .bento, .metrics, .cta"
  );
  if ("IntersectionObserver" in window && revealEls.length) {
    revealEls.forEach(function (el) {
      el.classList.add("reveal");
    });
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1 }
    );
    revealEls.forEach(function (el) {
      io.observe(el);
    });
  }

  /* --------------------------------------------------------------------- Year */
  var year = document.getElementById("year");
  if (year) year.textContent = String(new Date().getFullYear());
})();
