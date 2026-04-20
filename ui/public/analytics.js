// analytics.js - Telemetry Intelligence Dashboard
// Loaded after app.js; patches renderData to auto-rebuild charts.

(function () {
    'use strict';

    // Wait for DOMContentLoaded to ensure app.js ran first
    document.addEventListener('DOMContentLoaded', function () {

        Chart.defaults.font = { family: "'Inter', sans-serif", size: 11 };
        Chart.defaults.color = '#a0a6b5';

        var PALETTE = {
            critical: '#f03e3e',
            high:     '#f59f00',
            medium:   '#5e6ad2',
            unknown:  '#444860',
            bars: [
                'rgba(94,106,210,0.85)',  'rgba(80,250,123,0.75)',
                'rgba(245,159,0,0.80)',   'rgba(240,62,62,0.80)',
                'rgba(189,147,249,0.80)', 'rgba(255,184,108,0.80)',
                'rgba(8,189,189,0.80)',   'rgba(255,121,198,0.80)',
                'rgba(68,184,204,0.80)',  'rgba(98,209,150,0.80)',
                'rgba(255,100,100,0.80)', 'rgba(130,200,255,0.80)',
                'rgba(255,220,80,0.80)',  'rgba(200,130,255,0.80)',
                'rgba(255,160,80,0.80)',
            ]
        };

        var TOOLTIP_STYLE = {
            backgroundColor: 'rgba(15,17,26,0.95)',
            borderColor: 'rgba(94,106,210,0.4)',
            borderWidth: 1,
            titleFont: { family: "'Inter', sans-serif", weight: '600', size: 12 },
            bodyFont:  { family: "'Inter', sans-serif", size: 11 },
            padding: 10,
            cornerRadius: 6
        };

        var _charts = { severity: null, types: null, processes: null, integrity: null };

        function destroyChart(c) {
            if (c) { try { c.destroy(); } catch (e) {} }
        }

        function buildAnalytics(hcData, cogData) {
            var all = hcData.concat(cogData);
            var hasData = all.length > 0;

            var grid     = document.getElementById('analyticsGrid');
            var strip    = document.getElementById('analyticsStatStrip');
            var empty    = document.getElementById('analyticsEmpty');
            var subtitle = document.getElementById('analyticsSubtitle');

            if (!grid) return; // Panel not in DOM yet

            if (!hasData) {
                grid.classList.add('hidden');
                strip.classList.add('hidden');
                if (empty) empty.style.display = 'flex';
                if (subtitle) subtitle.textContent = 'Load a trace file to populate charts';
                return;
            }

            grid.classList.remove('hidden');
            strip.classList.remove('hidden');
            if (empty) empty.style.display = 'none';
            if (subtitle) subtitle.textContent = all.length.toLocaleString() + ' findings — ' + hcData.length.toLocaleString() + ' high-confidence, ' + cogData.length.toLocaleString() + ' cognitive targets';

            // Stat Strip
            var sevCounts = { critical: 0, high: 0, medium: 0 };
            var processSet = {};
            var typeSet    = {};

            all.forEach(function (item) {
                var sev = (item.Severity || '').toLowerCase();
                if (sev === 'critical')    sevCounts.critical++;
                else if (sev === 'high')   sevCounts.high++;
                else if (sev === 'medium') sevCounts.medium++;

                (item.Processes || '').split(',').forEach(function (p) {
                    var t = p.trim();
                    if (t) processSet[t.toLowerCase()] = true;
                });
                if (item.Type) typeSet[item.Type.trim()] = true;
            });

            function setEl(id, val) {
                var el = document.getElementById(id);
                if (el) el.textContent = val;
            }

            setEl('astatTotal',     all.length.toLocaleString());
            setEl('astatCritical',  sevCounts.critical.toLocaleString());
            setEl('astatHigh',      sevCounts.high.toLocaleString());
            setEl('astatMedium',    sevCounts.medium.toLocaleString());
            setEl('astatProcesses', Object.keys(processSet).length.toLocaleString());
            setEl('astatTypes',     Object.keys(typeSet).length.toLocaleString());

            // Chart 1 — Severity Donut
            destroyChart(_charts.severity);
            var sevCanvas = document.getElementById('chartSeverity');
            if (sevCanvas) {
                _charts.severity = new Chart(sevCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low / Other'],
                        datasets: [{
                            data: [
                                sevCounts.critical, sevCounts.high, sevCounts.medium,
                                Math.max(0, all.length - sevCounts.critical - sevCounts.high - sevCounts.medium)
                            ],
                            backgroundColor: [PALETTE.critical, PALETTE.high, PALETTE.medium, PALETTE.unknown],
                            borderColor: 'rgba(255,255,255,0.05)',
                            borderWidth: 2,
                            hoverOffset: 8
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        cutout: '64%',
                        animation: { duration: 600, easing: 'easeOutQuart' },
                        plugins: {
                            tooltip: TOOLTIP_STYLE,
                            legend: { position: 'right', labels: { color: '#a0a6b5', padding: 14, font: { size: 11 } } }
                        }
                    }
                });
            }

            // Chart 2 — Finding Types
            destroyChart(_charts.types);
            var typeCounts = {};
            all.forEach(function (item) {
                var t = (item.Type || 'Unknown').trim();
                typeCounts[t] = (typeCounts[t] || 0) + 1;
            });
            var sortedTypes = Object.entries(typeCounts).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 10);

            var typesCanvas = document.getElementById('chartTypes');
            if (typesCanvas) {
                _charts.types = new Chart(typesCanvas, {
                    type: 'bar',
                    data: {
                        labels: sortedTypes.map(function (e) { return e[0].length > 24 ? e[0].substring(0, 24) + '…' : e[0]; }),
                        datasets: [{
                            label: 'Findings',
                            data: sortedTypes.map(function (e) { return e[1]; }),
                            backgroundColor: sortedTypes.map(function (_, i) { return PALETTE.bars[i % PALETTE.bars.length]; }),
                            borderRadius: 5,
                            borderSkipped: false
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        indexAxis: 'y',
                        animation: { duration: 600 },
                        plugins: { tooltip: TOOLTIP_STYLE, legend: { display: false } },
                        scales: {
                            x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#a0a6b5' } },
                            y: { grid: { display: false }, ticks: { color: '#c4c8d4', font: { size: 10 } } }
                        }
                    }
                });
            }

            // Chart 3 — Top Processes
            destroyChart(_charts.processes);
            var procCounts = {};
            all.forEach(function (item) {
                (item.Processes || '').split(',').forEach(function (p) {
                    var t = p.trim().toLowerCase();
                    if (t) procCounts[t] = (procCounts[t] || 0) + 1;
                });
            });
            var sortedProcs = Object.entries(procCounts).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 15);

            var procsCanvas = document.getElementById('chartProcesses');
            if (procsCanvas) {
                _charts.processes = new Chart(procsCanvas, {
                    type: 'bar',
                    data: {
                        labels: sortedProcs.map(function (e) { return e[0].length > 32 ? e[0].substring(0, 32) + '…' : e[0]; }),
                        datasets: [{
                            label: 'Lead Count',
                            data: sortedProcs.map(function (e) { return e[1]; }),
                            backgroundColor: 'rgba(94,106,210,0.72)',
                            borderColor: 'rgba(94,106,210,1)',
                            borderWidth: 1,
                            borderRadius: 5,
                            borderSkipped: false,
                            hoverBackgroundColor: 'rgba(94,106,210,0.95)'
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        animation: { duration: 600 },
                        plugins: { tooltip: TOOLTIP_STYLE, legend: { display: false } },
                        scales: {
                            x: {
                                grid: { color: 'rgba(255,255,255,0.04)' },
                                ticks: { color: '#a0a6b5', font: { family: 'monospace', size: 10 } },
                                title: { display: true, text: 'Appearances in Leads', color: '#666', font: { size: 10 } }
                            },
                            y: { grid: { display: false }, ticks: { color: '#c4c8d4', font: { family: 'monospace', size: 10 } } }
                        }
                    }
                });
            }

            // Chart 4 — Integrity Level Donut
            destroyChart(_charts.integrity);
            var integCounts = {};
            all.forEach(function (item) {
                var lvl = (item.Integrity || 'Unknown').trim();
                integCounts[lvl] = (integCounts[lvl] || 0) + 1;
            });
            var integEntries = Object.entries(integCounts).sort(function (a, b) { return b[1] - a[1]; });
            var integColorMap = {
                'System': '#f03e3e', 'High': '#f59f00',
                'Medium Plus': '#50fa7b', 'Medium': '#5e6ad2',
                'Low': '#8be9fd', 'AppContainer': '#bd93f9', 'Unknown': '#444860'
            };

            var integCanvas = document.getElementById('chartIntegrity');
            if (integCanvas) {
                _charts.integrity = new Chart(integCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: integEntries.map(function (e) { return e[0]; }),
                        datasets: [{
                            data: integEntries.map(function (e) { return e[1]; }),
                            backgroundColor: integEntries.map(function (e, i) { return integColorMap[e[0]] || PALETTE.bars[i % PALETTE.bars.length]; }),
                            borderColor: 'rgba(255,255,255,0.05)',
                            borderWidth: 2,
                            hoverOffset: 8
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        cutout: '64%',
                        animation: { duration: 600, easing: 'easeOutQuart' },
                        plugins: {
                            tooltip: TOOLTIP_STYLE,
                            legend: { position: 'right', labels: { color: '#a0a6b5', padding: 14, font: { size: 11 } } }
                        }
                    }
                });
            }
        }

        // Expose so app.js can call it
        window.__buildAnalytics = buildAnalytics;

        // Initial empty state
        buildAnalytics([], []);

        // Poll for data once app.js has populated it (fires after loadProjectData resolves)
        // We use a custom event dispatched by a patched renderData in app.js
        document.addEventListener('analyticsDataReady', function (e) {
            buildAnalytics(e.detail.hc, e.detail.cog);
        });
    });

})();
