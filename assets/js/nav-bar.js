window.addEventListener('scroll', function () {
  var nav = document.querySelector('nav');
  if (!nav) return;
  nav.classList.toggle('scrolled', window.scrollY > 100);
});
