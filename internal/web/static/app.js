// Minimal progressive enhancement: select-all checkboxes, confirm prompts,
// and live run progress polling (no animation).
(function () {
  document.querySelectorAll('input[data-select-all]').forEach(function (cb) {
    cb.addEventListener('change', function () {
      document.querySelectorAll('input[name="id"]').forEach(function (x) { x.checked = cb.checked; });
    });
  });
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault();
    });
  });
  var live = document.querySelector('[data-live-runs]');
  if (live) {
    var hadRuns = live.getAttribute('data-live-runs') === '1';
    var poll = function () {
      fetch('/workers.json', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (runs) {
        runs = runs || [];
        if (hadRuns && runs.length === 0) { window.location.reload(); return; }
        runs.forEach(function (p) {
          var row = document.querySelector('[data-run="' + p.RunID + '"]');
          if (!row) { if (!hadRuns) window.location.reload(); return; }
          var pr = row.querySelector('progress');
          if (pr) { pr.max = p.Total || 1; pr.value = p.Done; }
          var t = row.querySelector('[data-f=count]');
          if (t) t.textContent = p.Done + '/' + p.Total + ' (' + (p.Total ? Math.floor(p.Done * 100 / p.Total) : 0) + '%)';
          var e = row.querySelector('[data-f=errors]');
          if (e) e.textContent = p.Errors;
          var ph = row.querySelector('[data-f=phase]');
          if (ph) ph.textContent = p.Phase;
          var el = row.querySelector('[data-f=elapsed]');
          if (el) el.textContent = p.Elapsed;
        });
        hadRuns = runs.length > 0;
      }).catch(function () {});
    };
    setInterval(poll, 3000);
  }
})();
