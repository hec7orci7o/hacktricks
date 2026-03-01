document$.subscribe(function () {
  document.querySelectorAll("span.md-tag").forEach(function (tag) {
    var slug = tag.textContent.trim().toLowerCase().replace(/\s+/g, "-");
    tag.setAttribute("data-tag", slug);
  });
});
