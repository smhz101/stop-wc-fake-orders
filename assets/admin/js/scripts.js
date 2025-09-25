/* scripts.js */
(function ($) {
  'use strict';

  // ---------- Helpers ----------
  function asArray(x) {
    if (Array.isArray(x)) return x;
    if (typeof x === 'string' && x.trim()) {
      try {
        return JSON.parse(x);
      } catch (e) {}
    }
    return [];
  }
  function toNumberArray(arr) {
    return arr.map(function (v) {
      var n = Number(v);
      return Number.isFinite(n) ? n : 0;
    });
  }
  function normalize(labels, data) {
    var L = Array.isArray(labels) ? labels : [];
    var D = Array.isArray(data) ? data : [];
    if (!L.length || !D.length) return { labels: ['–'], data: [0] };
    return { labels: L, data: D };
  }
  function esc(s) {
    return String(s);
  }
  function pad(n) {
    return n < 10 ? '0' + n : '' + n;
  }
  function formatTs(t) {
    var d = new Date(t * 1000);
    return (
      d.getFullYear() +
      '-' +
      pad(d.getMonth() + 1) +
      '-' +
      pad(d.getDate()) +
      ' ' +
      pad(d.getHours()) +
      ':' +
      pad(d.getMinutes()) +
      ':' +
      pad(d.getSeconds())
    );
  }

  // ---------- Charts ----------
  $(function initCharts() {
    if (!window.SWFOData || !SWFOData.charts) return;

    var charts = SWFOData.charts;

    var types = normalize(asArray(charts.typesLabels), toNumberArray(asArray(charts.typesData)));
    var hours = normalize(asArray(charts.hoursLabels), toNumberArray(asArray(charts.hoursData)));

    (function ready() {
      if (typeof window.Chart === 'undefined') return void setTimeout(ready, 40);

      var $types = $('#swfoTypes');
      var $hits = $('#swfoHits');

      if ($types.length) {
        new Chart($types[0], {
          type: 'bar',
          data: {
            labels: types.labels,
            datasets: [
              {
                label: 'Events (last 100)',
                data: types.data,
                borderWidth: 1,
                borderSkipped: false,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: { padding: 8 },
            plugins: {
              legend: { display: false },
              title: { display: true, text: 'Events (last 100)' },
              tooltip: { mode: 'index', intersect: false },
            },
            scales: {
              x: { ticks: { autoSkip: true, maxRotation: 0 } },
              y: { beginAtZero: true, ticks: { precision: 0 } },
            },
            animation: { duration: 250 },
          },
        });
      }

      if ($hits.length) {
        new Chart($hits[0], {
          type: 'line',
          data: {
            labels: hours.labels,
            datasets: [
              {
                label: 'REST hits (last 24h)',
                data: hours.data,
                borderWidth: 2,
                pointRadius: 2,
                cubicInterpolationMode: 'monotone',
                tension: 0.3,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: { padding: 8 },
            plugins: {
              legend: { display: false },
              title: { display: true, text: 'REST hits (last 24h)' },
              tooltip: { mode: 'index', intersect: false },
            },
            scales: {
              x: { title: { display: true, text: 'Hour' } },
              y: { beginAtZero: true, ticks: { precision: 0 } },
            },
            animation: { duration: 250 },
          },
        });
      }
    })();
  });

  // ---------- Live polling (events / apihits) ----------
  (function polling() {
    if (!window.SWFOData) return;

    var lastEventTs = 0;
    var lastHitTs = 0;
    var timer = null;
    var interval = Number(SWFOData.poll_interval || 300);

    function activeTab() {
      var $a = $('.nav-tab.nav-tab-active');
      return $a.length ? String($a.data('tab')) : 'status';
    }

    function start() {
      stop();
      timer = setInterval(tick, interval);
    }
    function stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    }
    function tick() {
      // Pause when tab not visible to avoid waste
      if (document.hidden) return;

      var tab = activeTab();
      if (tab === 'events') {
        getJSON('swfo_get_events', lastEventTs, function (items) {
          if (!items || !items.length) return;
          lastEventTs = Math.max.apply(
            null,
            items.map(function (i) {
              return i.t || 0;
            })
          );
          appendEvents(items);
        });
      } else if (tab === 'apihits') {
        getJSON('swfo_get_hits', lastHitTs, function (items) {
          if (!items || !items.length) return;
          lastHitTs = Math.max.apply(
            null,
            items.map(function (i) {
              return i.t || 0;
            })
          );
          appendHits(items);
        });
      }
    }

    function getJSON(action, since, cb) {
      $.ajax({
        url: SWFOData.ajax_url,
        method: 'GET',
        dataType: 'json',
        data: {
          action: action,
          since: since || 0,
          _ajax_nonce: SWFOData.nonce,
        },
      }).done(function (resp) {
        if (resp && resp.success && resp.data && resp.data.items) cb(resp.data.items);
      });
    }

    function appendEvents(items) {
      var $tbody = $('#swfo-events-body');
      if (!$tbody.length) return;
      items
        .slice()
        .reverse()
        .forEach(function (row) {
          var dt = row.t ? formatTs(row.t) : '';
          var type = esc(row.type || '');
          var note = esc(row.note || '');
          var $tr = $('<tr/>')
            .append($('<td/>').text(dt))
            .append($('<td/>').text(type))
            .append($('<td/>').text(note));
          $tbody.prepend($tr);
        });
      trimRows($tbody, 500);
    }

    function appendHits(items) {
      var $tbody = $('#swfo-hits-body');
      if (!$tbody.length) return;
      items
        .slice()
        .reverse()
        .forEach(function (h) {
          var dt = h.t ? formatTs(h.t) : '';
          var ip = esc(h.ip || '');
          var m = esc((h.m || '').toUpperCase());
          var p = esc(h.path || h.route || '');
          var d =
            typeof h.data === 'object'
              ? JSON.stringify(h.data).slice(0, 3000)
              : String(h.data || '');
          var $tr = $('<tr/>')
            .append($('<td/>').text(dt))
            .append($('<td/>').append($('<code/>').text(ip)))
            .append($('<td/>').text(m))
            .append($('<td/>').append($('<code/>').text(p)))
            .append(
              $('<td/>').append(
                $(
                  '<code style="white-space:pre-wrap;word-break:break-word;display:block;max-height:6.5em;overflow:auto;"/>'
                ).text(d)
              )
            );
          $tbody.prepend($tr);
        });
      trimRows($tbody, 500);
    }

    function trimRows($tbody, limit) {
      var $rows = $tbody.find('tr');
      if ($rows.length > limit) $rows.slice(limit).remove();
    }

    // Tab click: start/stop polling by active tab
    $(document).on('click', '.nav-tab', function () {
      setTimeout(function () {
        var tab = activeTab();
        if (tab === 'events' || tab === 'apihits') start();
        else stop();
      }, 0);
    });

    // Init
    $(function () {
      // Optionally prime timestamps if tables already have rows
      if ($('#swfo-events-body tr:first').length) lastEventTs = Math.floor(Date.now() / 1000);
      if ($('#swfo-hits-body tr:first').length) lastHitTs = Math.floor(Date.now() / 1000);

      var tab = activeTab();
      if (tab === 'events' || tab === 'apihits') start();
    });

    // Pause on unload/visibility change
    $(window).on('beforeunload', stop);
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop();
      else {
        var tab = activeTab();
        if (tab === 'events' || tab === 'apihits') start();
      }
    });
  })();
})(jQuery);
