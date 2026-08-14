// Pahlevan site interactions
document.addEventListener('DOMContentLoaded', function () {
  setupMobileNav();
  setupNavbarScroll();
  addCopyButtons();
  setCurrentYear();
});

// Mobile navigation toggle
function setupMobileNav() {
  const navToggle = document.querySelector('.nav-toggle');
  const navLinks = document.querySelector('.nav-links');
  if (!navToggle || !navLinks) return;

  navToggle.addEventListener('click', function () {
    const open = navLinks.classList.toggle('active');
    navToggle.classList.toggle('active', open);
    navToggle.setAttribute('aria-expanded', String(open));
  });

  // Close the menu after choosing a link
  navLinks.querySelectorAll('a').forEach(function (link) {
    link.addEventListener('click', function () {
      navLinks.classList.remove('active');
      navToggle.classList.remove('active');
      navToggle.setAttribute('aria-expanded', 'false');
    });
  });
}

// Solidify the navbar background once the page is scrolled
function setupNavbarScroll() {
  const navbar = document.querySelector('.navbar');
  if (!navbar) return;

  let ticking = false;
  function update() {
    navbar.style.boxShadow = window.scrollY > 20 ? '0 8px 24px -12px rgba(0,0,0,0.7)' : 'none';
    ticking = false;
  }
  window.addEventListener('scroll', function () {
    if (!ticking) {
      window.requestAnimationFrame(update);
      ticking = true;
    }
  });
  update();
}

// Copy-to-clipboard buttons on every code block
function addCopyButtons() {
  document.querySelectorAll('.code-block pre').forEach(function (block) {
    const wrap = block.parentElement;
    wrap.style.position = 'relative';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-button';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code to clipboard');
    button.style.cssText =
      'position:absolute;top:10px;right:10px;background:rgba(255,255,255,0.06);' +
      'border:1px solid rgba(255,255,255,0.15);color:#cbd5e1;padding:0.35rem 0.6rem;' +
      'border-radius:0.35rem;cursor:pointer;font-size:0.72rem;font-family:inherit;' +
      'opacity:0;transition:opacity 0.2s ease;';

    wrap.addEventListener('mouseenter', function () { button.style.opacity = '1'; });
    wrap.addEventListener('mouseleave', function () { button.style.opacity = '0'; });
    button.addEventListener('focus', function () { button.style.opacity = '1'; });
    button.addEventListener('blur', function () { button.style.opacity = '0'; });

    button.addEventListener('click', function () {
      const code = block.textContent;
      const done = function () {
        button.textContent = 'Copied!';
        setTimeout(function () { button.textContent = 'Copy'; }, 2000);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(code).then(done).catch(function () {});
      } else {
        const ta = document.createElement('textarea');
        ta.value = code;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); done(); } catch (e) {}
        document.body.removeChild(ta);
      }
    });

    wrap.appendChild(button);
  });
}

function setCurrentYear() {
  const el = document.getElementById('year');
  if (el) el.textContent = String(new Date().getFullYear());
}
