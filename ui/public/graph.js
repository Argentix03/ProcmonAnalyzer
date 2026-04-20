// graph.js - Relationship Graph Explorer
// Provides 4 interactive graph types: Force Network, Heat Matrix, Flow Chart, Chord Diagram

(function () {
    'use strict';

    var _graphData = [];     // all loaded items (hc + cog)
    var _activeChart = null; // Chart.js instance for matrix/flow modes
    var _simulation = null;  // D3 force simulation
    var _zoom = null;        // D3 zoom behavior
    var _currentType = 'force';
    var _selectedNode = null;

    var COLORS = [
        '#5e6ad2','#50fa7b','#f59f00','#f03e3e','#bd93f9',
        '#ffb86c','#08bdbd','#ff79c6','#44b8cc','#62d196',
        '#ff6464','#82c8ff','#ffdc50','#c882ff','#ffa050',
        '#5ef0a0','#f08040','#40c0ff','#ff50a0','#a0ff50'
    ];

    var SEV_COLOR = { critical:'#f03e3e', high:'#f59f00', medium:'#5e6ad2', low:'#50fa7b', unknown:'#444860' };
    var INTEG_COLOR = { 'system':'#f03e3e','high':'#f59f00','medium plus':'#50fa7b','medium':'#5e6ad2','low':'#8be9fd','appcontainer':'#bd93f9','unknown':'#444860' };

    // Tooltip shared element
    var _tooltip = null;

    function getTooltip() {
        if (!_tooltip) {
            _tooltip = document.createElement('div');
            _tooltip.style.cssText = 'position:fixed;background:rgba(15,17,26,0.96);border:1px solid rgba(94,106,210,0.5);border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#e4e6eb;pointer-events:none;z-index:9999;display:none;max-width:220px;line-height:1.5;font-family:Inter,sans-serif;';
            document.body.appendChild(_tooltip);
        }
        return _tooltip;
    }

    function showTooltip(html, x, y) {
        var t = getTooltip();
        t.innerHTML = html;
        t.style.display = 'block';
        t.style.left = (x + 14) + 'px';
        t.style.top  = (y - 10) + 'px';
    }

    function hideTooltip() {
        getTooltip().style.display = 'none';
    }

    // Extract values for a given field from one item
    function getFieldValues(item, field) {
        if (field === 'Processes') {
            return (item.Processes || '').split(',').map(function(p){ return p.trim().toLowerCase(); }).filter(Boolean);
        }
        if (field === 'Severity') {
            var s = (item.Severity || 'Unknown').trim();
            return [s.charAt(0).toUpperCase() + s.slice(1)];
        }
        if (field === 'Integrity') {
            return [(item.Integrity || 'Unknown').trim()];
        }
        if (field === 'Type') {
            return [(item.Type || 'Unknown').trim()];
        }
        if (field === 'Operation') {
            return [(item.Operation || 'Unknown').trim()];
        }
        return ['Unknown'];
    }

    // Build pair co-occurrence map: { "A||B": count }
    function buildPairMap(data, srcField, tgtField, maxSrc, maxTgt) {
        var srcCount = {}, tgtCount = {};
        data.forEach(function(item) {
            getFieldValues(item, srcField).forEach(function(v){ srcCount[v] = (srcCount[v]||0)+1; });
            getFieldValues(item, tgtField).forEach(function(v){ tgtCount[v] = (tgtCount[v]||0)+1; });
        });

        // Top N by frequency
        var topSrc = Object.entries(srcCount).sort(function(a,b){return b[1]-a[1];}).slice(0,maxSrc).map(function(e){return e[0];});
        var topTgt = Object.entries(tgtCount).sort(function(a,b){return b[1]-a[1];}).slice(0,maxTgt).map(function(e){return e[0];});

        var topSrcSet = new Set(topSrc);
        var topTgtSet = new Set(topTgt);
        var pairs = {};

        data.forEach(function(item) {
            var srcs = getFieldValues(item, srcField).filter(function(v){return topSrcSet.has(v);});
            var tgts = getFieldValues(item, tgtField).filter(function(v){return topTgtSet.has(v);});
            srcs.forEach(function(s) {
                tgts.forEach(function(t) {
                    if (s === t) return; // skip self
                    var k = s + '||' + t;
                    pairs[k] = (pairs[k]||0) + 1;
                });
            });
        });

        return { pairs: pairs, topSrc: topSrc, topTgt: topTgt, srcCount: srcCount, tgtCount: tgtCount };
    }

    // Color helpers
    function colorForValue(field, value) {
        var v = value.toLowerCase();
        if (field === 'Severity') return SEV_COLOR[v] || COLORS[0];
        if (field === 'Integrity') return INTEG_COLOR[v] || COLORS[3];
        return null; // will use indexed palette
    }

    function makeColorMap(values, field) {
        var map = {};
        values.forEach(function(v, i) {
            map[v] = colorForValue(field, v) || COLORS[i % COLORS.length];
        });
        return map;
    }

    // ===========================
    // MODE 1: Force-Directed Network
    // ===========================
    function buildForceGraph(data, srcField, tgtField, maxNodes) {
        clearD3();
        showSvg();

        var maxEach = Math.ceil(maxNodes / 2);
        var result = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var pairs = result.pairs;
        var topSrc = result.topSrc;
        var topTgt = result.topTgt;
        var srcCount = result.srcCount;
        var tgtCount = result.tgtCount;

        // Build nodes list (deduplicated - a value can appear in both if same field)
        var nodeMap = {};
        topSrc.forEach(function(v) { nodeMap[v+':src'] = { id: v+'::src', label: v, group: 'src', count: srcCount[v]||0 }; });
        topTgt.forEach(function(v) { if (!nodeMap[v+':src']) nodeMap[v+':tgt'] = { id: v+'::tgt', label: v, group: 'tgt', count: tgtCount[v]||0 }; });

        var nodes = Object.values(nodeMap);
        var nodeById = {};
        nodes.forEach(function(n){ nodeById[n.id] = n; });

        // Build edges
        var links = [];
        Object.entries(pairs).forEach(function(entry) {
            var parts = entry[0].split('||');
            var s = parts[0]; var t = parts[1]; var w = entry[1];
            var srcId = s+'::src';
            var tgtId = (nodeById[t+'::src'] ? t+'::src' : t+'::tgt');
            if (nodeById[srcId] && nodeById[tgtId]) {
                links.push({ source: srcId, target: tgtId, value: w });
            }
        });

        if (nodes.length === 0) { showGraphEmpty(true); return; }
        showGraphEmpty(false);

        var srcColorMap = makeColorMap(topSrc, srcField);
        var tgtColorMap = makeColorMap(topTgt, tgtField);

        var svg = d3.select('#graphSvg');
        var wrap = document.getElementById('graphCanvasWrap');
        var W = wrap.clientWidth || 800;
        var H = wrap.clientHeight || 500;

        svg.attr('viewBox', '0 0 ' + W + ' ' + H);

        var g = svg.append('g').attr('class', 'graph-root');

        // Zoom
        _zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', function(event) {
            g.attr('transform', event.transform);
        });
        svg.call(_zoom);

        // Link width scale
        var maxVal = Math.max.apply(null, links.map(function(l){return l.value;})) || 1;
        var wScale = d3.scaleLinear().domain([1, maxVal]).range([1, 7]);

        // Draw links
        var link = g.append('g').attr('fill','none').selectAll('line')
            .data(links).enter().append('line')
            .attr('class','g-link')
            .attr('stroke', function(d) {
                var src = d.source.id || d.source;
                return srcColorMap[src.replace('::src','').replace('::tgt','')] || '#5e6ad2';
            })
            .attr('stroke-width', function(d){ return wScale(d.value); })
            .on('mousemove', function(event, d) {
                var src = (d.source.id||d.source).replace('::src','').replace('::tgt','');
                var tgt = (d.target.id||d.target).replace('::src','').replace('::tgt','');
                showTooltip('<strong>' + src + '</strong> → <strong>' + tgt + '</strong><br>Co-occurrences: <strong style="color:#50fa7b">' + d.value + '</strong>', event.clientX, event.clientY);
            })
            .on('mouseleave', hideTooltip);

        // Node radius scale
        var allCounts = nodes.map(function(n){return n.count;});
        var maxCount = Math.max.apply(null, allCounts) || 1;
        var rScale = d3.scaleSqrt().domain([1, maxCount]).range([6, 28]);

        // Draw nodes
        var node = g.append('g').selectAll('.g-node')
            .data(nodes).enter().append('g')
            .attr('class','g-node')
            .call(d3.drag()
                .on('start', function(event, d) {
                    if (!event.active) _simulation.alphaTarget(0.3).restart();
                    d.fx = d.x; d.fy = d.y;
                })
                .on('drag', function(event, d) {
                    d.fx = event.x; d.fy = event.y;
                })
                .on('end', function(event, d) {
                    if (!event.active) _simulation.alphaTarget(0);
                    d.fx = null; d.fy = null;
                })
            )
            .on('click', function(event, d) {
                event.stopPropagation();
                _selectedNode = d.id;
                highlightNode(d, node, link, srcColorMap, tgtColorMap);
                showInfoPanel(d, srcField, tgtField, links);
            })
            .on('mousemove', function(event, d) {
                showTooltip('<strong>' + d.label + '</strong><br>' + d.group.toUpperCase() + ' field · Count: <strong style="color:#50fa7b">' + d.count.toLocaleString() + '</strong>', event.clientX, event.clientY);
            })
            .on('mouseleave', hideTooltip);

        node.append('circle')
            .attr('r', function(d){ return rScale(d.count); })
            .attr('fill', function(d) {
                var c = d.group === 'src' ? srcColorMap[d.label] : tgtColorMap[d.label];
                return c || '#5e6ad2';
            })
            .attr('fill-opacity', 0.85)
            .attr('stroke', '#fff')
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.2);

        node.append('text')
            .attr('dy', function(d){ return rScale(d.count) + 13; })
            .attr('text-anchor', 'middle')
            .attr('font-size', '10px')
            .attr('fill', '#a0a6b5')
            .text(function(d){ return d.label.length > 18 ? d.label.substring(0,18)+'…' : d.label; });

        // Click background to deselect
        svg.on('click', function() {
            _selectedNode = null;
            node.classed('dimmed', false);
            link.classed('dimmed', false).classed('highlighted', false);
            document.getElementById('graphInfoPanel').classList.add('hidden');
        });

        // Force simulation
        _simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 80 + 120 / (d.value+1);}).strength(0.6))
            .force('charge', d3.forceManyBody().strength(-220))
            .force('center', d3.forceCenter(W/2, H/2))
            .force('collision', d3.forceCollide().radius(function(d){return rScale(d.count)+8;}))
            .on('tick', function() {
                link.attr('x1', function(d){return d.source.x;})
                    .attr('y1', function(d){return d.source.y;})
                    .attr('x2', function(d){return d.target.x;})
                    .attr('y2', function(d){return d.target.y;});
                node.attr('transform', function(d){return 'translate('+d.x+','+d.y+')';});
            });

        // Build legend
        buildLegend(topSrc, srcField, srcColorMap, topTgt, tgtField, tgtColorMap, 'src/tgt');
    }

    function highlightNode(d, nodeSel, linkSel, srcColorMap, tgtColorMap) {
        var connected = new Set([d.id]);
        linkSel.each(function(l) {
            var s = l.source.id || l.source;
            var t = l.target.id || l.target;
            if (s === d.id || t === d.id) { connected.add(s); connected.add(t); }
        });
        nodeSel.classed('dimmed', function(n){ return !connected.has(n.id); });
        linkSel.classed('dimmed', function(l) {
            var s = l.source.id||l.source; var t = l.target.id||l.target;
            return !(s === d.id || t === d.id);
        }).classed('highlighted', function(l) {
            var s = l.source.id||l.source; var t = l.target.id||l.target;
            return s === d.id || t === d.id;
        });
    }

    function showInfoPanel(d, srcField, tgtField, links) {
        var panel = document.getElementById('graphInfoPanel');
        var title = document.getElementById('graphInfoTitle');
        var body  = document.getElementById('graphInfoBody');
        title.textContent = d.label;
        var connections = links.filter(function(l){
            return (l.source.id||l.source) === d.id || (l.target.id||l.target) === d.id;
        });
        var html = '<div class="graph-info-row"><span>Field</span><strong>' + (d.group === 'src' ? srcField : tgtField) + '</strong></div>';
        html += '<div class="graph-info-row"><span>Appearances</span><strong>' + d.count.toLocaleString() + '</strong></div>';
        html += '<div class="graph-info-row"><span>Connections</span><strong>' + connections.length + '</strong></div>';

        // Top partners
        var sortedConns = connections.slice().sort(function(a,b){return b.value-a.value;}).slice(0,5);
        if (sortedConns.length > 0) {
            html += '<hr style="border-color:rgba(255,255,255,0.06); margin:4px 0;">';
            html += '<div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em; color:#6a7090; margin-bottom:4px;">Top Partners</div>';
            sortedConns.forEach(function(l) {
                var s = (l.source.id||l.source).replace('::src','').replace('::tgt','');
                var t = (l.target.id||l.target).replace('::src','').replace('::tgt','');
                var partner = (s === d.label) ? t : s;
                html += '<div class="graph-info-row"><span>' + (partner.length>16?partner.substring(0,16)+'…':partner) + '</span><strong>' + l.value + '</strong></div>';
            });
        }
        body.innerHTML = html;
        panel.classList.remove('hidden');
    }

    // ===========================
    // MODE 2: Heat Matrix
    // ===========================
    function buildMatrixGraph(data, srcField, tgtField, maxNodes) {
        clearD3();
        showChartCanvas();

        var maxEach = Math.min(maxNodes, 20);
        var result = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var topSrc = result.topSrc;
        var topTgt = result.topTgt;
        var pairs  = result.pairs;

        if (topSrc.length === 0 || topTgt.length === 0) { showGraphEmpty(true); return; }
        showGraphEmpty(false);

        // Build bubble dataset
        var datasets = [];
        var maxVal = 0;
        Object.values(pairs).forEach(function(v){ if(v>maxVal) maxVal=v; });

        var srcColorMap = makeColorMap(topSrc, srcField);

        topSrc.forEach(function(src, si) {
            var dataPts = [];
            topTgt.forEach(function(tgt, ti) {
                var k = src + '||' + tgt;
                var v = pairs[k] || 0;
                dataPts.push({ x: tgt, y: src, v: v, r: v > 0 ? Math.max(4, (v / maxVal) * 28) : 0 });
            });
            datasets.push({
                label: src,
                data: dataPts,
                backgroundColor: (srcColorMap[src] || COLORS[si % COLORS.length]).replace(')', ',0.75)').replace('rgb', 'rgba'),
                borderColor: srcColorMap[src] || COLORS[si % COLORS.length],
                borderWidth: 1
            });
        });

        if (_activeChart) { try { _activeChart.destroy(); } catch(e){} }
        _activeChart = new Chart(document.getElementById('graphChartCanvas'), {
            type: 'bubble',
            data: { datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 500 },
                parsing: false,
                scales: {
                    x: {
                        type: 'category',
                        labels: topTgt,
                        title: { display: true, text: tgtField, color:'#a0a6b5', font:{size:11} },
                        grid: { color:'rgba(255,255,255,0.04)' },
                        ticks: { color:'#c4c8d4', font:{size:10}, maxRotation:40 }
                    },
                    y: {
                        type: 'category',
                        labels: topSrc.slice().reverse(),
                        title: { display: true, text: srcField, color:'#a0a6b5', font:{size:11} },
                        grid: { color:'rgba(255,255,255,0.04)' },
                        ticks: { color:'#c4c8d4', font:{size:10} }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor:'rgba(15,17,26,0.96)',
                        borderColor:'rgba(94,106,210,0.4)',
                        borderWidth: 1,
                        callbacks: {
                            label: function(ctx) {
                                var d = ctx.raw;
                                return d.y + ' → ' + d.x + ': ' + d.v + ' co-occurrences';
                            }
                        }
                    }
                }
            }
        });

        buildLegend(topSrc, srcField, srcColorMap, null, null, null, 'src');
        document.getElementById('graphZoomBtns').classList.add('hidden');
    }

    // ===========================
    // MODE 3: Stacked Flow Chart
    // ===========================
    function buildFlowGraph(data, srcField, tgtField, maxNodes) {
        clearD3();
        showChartCanvas();

        var maxSrc = Math.min(maxNodes, 16);
        var result = buildPairMap(data, srcField, tgtField, maxSrc, 20);
        var topSrc = result.topSrc;
        var topTgt = result.topTgt;
        var pairs  = result.pairs;

        if (topSrc.length === 0) { showGraphEmpty(true); return; }
        showGraphEmpty(false);

        var tgtColorMap = makeColorMap(topTgt, tgtField);

        var datasets = topTgt.map(function(tgt, ti) {
            return {
                label: tgt,
                data: topSrc.map(function(src) { return pairs[src+'||'+tgt] || 0; }),
                backgroundColor: (tgtColorMap[tgt] || COLORS[ti%COLORS.length]),
                borderColor: 'rgba(0,0,0,0.2)',
                borderWidth: 1,
                borderRadius: 3
            };
        });

        if (_activeChart) { try { _activeChart.destroy(); } catch(e){} }
        _activeChart = new Chart(document.getElementById('graphChartCanvas'), {
            type: 'bar',
            data: {
                labels: topSrc.map(function(s){ return s.length>20?s.substring(0,20)+'…':s; }),
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 500 },
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color:'#a0a6b5', font:{size:10}, padding:10,
                            generateLabels: function(chart) {
                                return topTgt.map(function(t, i) {
                                    return { text: t.length>20?t.substring(0,20)+'…':t, fillStyle: tgtColorMap[t]||COLORS[i%COLORS.length], strokeStyle:'transparent', index:i };
                                });
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor:'rgba(15,17,26,0.96)',
                        borderColor:'rgba(94,106,210,0.4)',
                        borderWidth:1
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: { color:'rgba(255,255,255,0.04)' },
                        ticks: { color:'#c4c8d4', font:{family:'monospace', size:9} },
                        title: { display: true, text: srcField, color:'#a0a6b5', font:{size:11} }
                    },
                    y: {
                        stacked: true,
                        grid: { color:'rgba(255,255,255,0.04)' },
                        ticks: { color:'#a0a6b5' },
                        title: { display: true, text: 'Count', color:'#a0a6b5', font:{size:11} }
                    }
                }
            }
        });

        document.getElementById('graphZoomBtns').classList.add('hidden');
    }

    // ===========================
    // MODE 4: Chord Diagram (D3)
    // ===========================
    function buildChordGraph(data, srcField, tgtField, maxNodes) {
        clearD3();
        showSvg();

        // For chord: treat src+tgt as one set of categories
        var maxEach = Math.min(Math.ceil(maxNodes/2), 12);
        var result = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var allKeys = result.topSrc.slice();
        result.topTgt.forEach(function(k){ if(allKeys.indexOf(k)<0) allKeys.push(k); });
        allKeys = allKeys.slice(0, maxNodes);

        if (allKeys.length < 2) { showGraphEmpty(true); return; }
        showGraphEmpty(false);

        var n = allKeys.length;
        var matrix = allKeys.map(function(){ return allKeys.map(function(){ return 0; }); });

        Object.entries(result.pairs).forEach(function(entry) {
            var pts = entry[0].split('||');
            var si = allKeys.indexOf(pts[0]);
            var ti = allKeys.indexOf(pts[1]);
            if (si>=0 && ti>=0) { matrix[si][ti] += entry[1]; matrix[ti][si] += entry[1]; }
        });

        var svg = d3.select('#graphSvg');
        var wrap = document.getElementById('graphCanvasWrap');
        var W = wrap.clientWidth || 800;
        var H = wrap.clientHeight || 500;
        var size = Math.min(W, H);
        var outerR = size * 0.44;
        var innerR = outerR - 22;

        svg.attr('viewBox', '0 0 ' + W + ' ' + H);
        var g = svg.append('g').attr('transform', 'translate(' + W/2 + ',' + H/2 + ')');

        _zoom = d3.zoom().scaleExtent([0.4,4]).on('zoom', function(event) {
            g.attr('transform', 'translate(' + W/2 + ',' + H/2 + ') scale(' + event.transform.k + ')');
        });
        svg.call(_zoom);

        var colorMap = makeColorMap(allKeys, srcField);

        var chord = d3.chord().padAngle(0.04).sortSubgroups(d3.descending)(matrix);

        // Arcs
        var arc = d3.arc().innerRadius(innerR).outerRadius(outerR);
        var ribbon = d3.ribbon().radius(innerR - 2);

        // Groups
        g.append('g').selectAll('g')
            .data(chord.groups).enter().append('g')
            .each(function(d) {
                d3.select(this).append('path')
                    .attr('d', arc)
                    .attr('fill', function(){ return colorMap[allKeys[d.index]] || COLORS[d.index%COLORS.length]; })
                    .attr('stroke', 'rgba(0,0,0,0.2)')
                    .attr('fill-opacity', 0.9)
                    .on('mousemove', function(event) {
                        showTooltip('<strong>' + allKeys[d.index] + '</strong><br>Total flow: ' + d.value.toLocaleString(), event.clientX, event.clientY);
                    })
                    .on('mouseleave', hideTooltip);

                // Labels
                var angle = (d.startAngle + d.endAngle) / 2;
                var labelR = outerR + 14;
                d3.select(this).append('text')
                    .attr('transform', 'rotate(' + ((angle * 180 / Math.PI) - 90) + ') translate(' + labelR + ',0)' + (angle > Math.PI ? ' rotate(180)' : ''))
                    .attr('text-anchor', angle > Math.PI ? 'end' : 'start')
                    .attr('font-size', '10px')
                    .attr('fill', '#a0a6b5')
                    .text(function(){ var l = allKeys[d.index]; return l.length>14?l.substring(0,14)+'…':l; });
            });

        // Ribbons
        g.append('g').attr('fill-opacity', 0.55).selectAll('path')
            .data(chord).enter().append('path')
            .attr('class','g-chord')
            .attr('d', ribbon)
            .attr('fill', function(d){ return colorMap[allKeys[d.source.index]] || COLORS[d.source.index%COLORS.length]; })
            .attr('stroke', 'rgba(0,0,0,0.15)')
            .on('mousemove', function(event, d) {
                showTooltip('<strong>' + allKeys[d.source.index] + '</strong> ↔ <strong>' + allKeys[d.target.index] + '</strong><br>Strength: ' + d.source.value.toLocaleString(), event.clientX, event.clientY);
            })
            .on('mouseleave', hideTooltip);

        buildLegend(allKeys, srcField, colorMap, null, null, null, 'all');
    }

    // ===========================
    // Legend builder
    // ===========================
    function buildLegend(srcKeys, srcField, srcColorMap, tgtKeys, tgtField, tgtColorMap, mode) {
        var legend = document.getElementById('graphLegend');
        if (!legend) return;
        legend.innerHTML = '';

        function addItems(keys, colorMap, label) {
            if (!keys || keys.length === 0) return;
            if (label) {
                var sep = document.createElement('span');
                sep.style.cssText = 'font-size:0.7rem; text-transform:uppercase; letter-spacing:0.06em; color:#555a70; font-weight:700; align-self:center;';
                sep.textContent = label + ':';
                legend.appendChild(sep);
            }
            keys.slice(0, 12).forEach(function(k) {
                var item = document.createElement('div');
                item.className = 'graph-legend-item';
                var dot = document.createElement('div');
                dot.className = 'graph-legend-dot';
                dot.style.background = colorMap[k] || '#5e6ad2';
                var txt = document.createElement('span');
                txt.textContent = k.length > 22 ? k.substring(0,22)+'…' : k;
                item.appendChild(dot); item.appendChild(txt);
                legend.appendChild(item);
            });
        }

        if (mode === 'src/tgt') {
            addItems(srcKeys, srcColorMap, srcField);
            if (tgtKeys && tgtField) addItems(tgtKeys, tgtColorMap, tgtField);
        } else {
            addItems(srcKeys, srcColorMap, '');
        }
        legend.classList.remove('hidden');
    }

    // ===========================
    // DOM helpers
    // ===========================
    function clearD3() {
        if (_simulation) { _simulation.stop(); _simulation = null; }
        d3.select('#graphSvg').selectAll('*').remove();
        if (_activeChart) { try { _activeChart.destroy(); } catch(e){} _activeChart = null; }
        document.getElementById('graphInfoPanel').classList.add('hidden');
        document.getElementById('graphLegend').classList.add('hidden');
        document.getElementById('graphLegend').innerHTML = '';
        document.getElementById('graphZoomBtns').classList.remove('hidden');
        hideTooltip();
    }

    function showSvg() {
        document.getElementById('graphSvg').style.display = 'block';
        document.getElementById('graphChartCanvas').classList.add('hidden');
    }

    function showChartCanvas() {
        document.getElementById('graphSvg').style.display = 'none';
        document.getElementById('graphChartCanvas').classList.remove('hidden');
    }

    function showGraphEmpty(empty) {
        var el = document.getElementById('graphEmpty');
        if (el) el.style.display = empty ? 'flex' : 'none';
        document.getElementById('graphLoading').classList.add('hidden');
    }

    function showLoading() {
        document.getElementById('graphLoading').classList.remove('hidden');
    }

    // ===========================
    // Main dispatcher
    // ===========================
    function buildGraph(type) {
        var data = _graphData;
        if (!data || data.length === 0) { showGraphEmpty(true); return; }

        var srcField = document.getElementById('graphSourceField').value;
        var tgtField = document.getElementById('graphTargetField').value;
        var maxNodes = parseInt(document.getElementById('graphMaxNodes').value) || 30;

        if (srcField === tgtField) {
            showGraphEmpty(false);
            d3.select('#graphSvg').selectAll('*').remove();
            var svg = d3.select('#graphSvg');
            var wrap = document.getElementById('graphCanvasWrap');
            svg.append('text')
                .attr('x', (wrap.clientWidth||800)/2)
                .attr('y', (wrap.clientHeight||400)/2)
                .attr('text-anchor','middle')
                .attr('fill','#a0a6b5')
                .attr('font-size','14px')
                .attr('font-family','Inter,sans-serif')
                .text('Source and Target fields must be different.');
            showSvg();
            return;
        }

        _currentType = type;
        showLoading();

        setTimeout(function() {
            try {
                if (type === 'force')  buildForceGraph(data, srcField, tgtField, maxNodes);
                else if (type === 'matrix') buildMatrixGraph(data, srcField, tgtField, maxNodes);
                else if (type === 'sankey') buildFlowGraph(data, srcField, tgtField, maxNodes);
                else if (type === 'chord')  buildChordGraph(data, srcField, tgtField, maxNodes);
            } catch(e) {
                console.error('[Graph] Build error:', e);
                showGraphEmpty(true);
            }
            document.getElementById('graphLoading').classList.add('hidden');
        }, 60);
    }

    // ===========================
    // Wire up controls
    // ===========================
    document.addEventListener('DOMContentLoaded', function() {

        // Type picker
        var picker = document.getElementById('graphTypePicker');
        if (picker) {
            picker.addEventListener('click', function(e) {
                var btn = e.target.closest('.gtype-btn');
                if (!btn) return;
                picker.querySelectorAll('.gtype-btn').forEach(function(b){ b.classList.remove('active'); });
                btn.classList.add('active');
                _currentType = btn.dataset.type;
                buildGraph(_currentType);
            });
        }

        // Rebuild button
        var refreshBtn = document.getElementById('graphRefreshBtn');
        if (refreshBtn) refreshBtn.addEventListener('click', function(){ buildGraph(_currentType); });

        // Max nodes slider
        var slider = document.getElementById('graphMaxNodes');
        var sliderVal = document.getElementById('graphMaxNodesVal');
        if (slider) {
            slider.addEventListener('input', function() {
                if (sliderVal) sliderVal.textContent = slider.value;
            });
            slider.addEventListener('change', function() {
                buildGraph(_currentType);
            });
        }

        // Zoom buttons
        document.getElementById('graphZoomIn').addEventListener('click', function() {
            if (_zoom) d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy, 1.4);
        });
        document.getElementById('graphZoomOut').addEventListener('click', function() {
            if (_zoom) d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy, 0.7);
        });
        document.getElementById('graphZoomReset').addEventListener('click', function() {
            if (_zoom) d3.select('#graphSvg').transition().duration(350).call(_zoom.transform, d3.zoomIdentity);
        });

        // Info panel close
        document.getElementById('graphInfoClose').addEventListener('click', function() {
            document.getElementById('graphInfoPanel').classList.add('hidden');
        });

        // Listen for data
        document.addEventListener('analyticsDataReady', function(e) {
            _graphData = (e.detail.hc || []).concat(e.detail.cog || []);
            // Only rebuild if graph panel is currently active
            var panel = document.getElementById('graphPanel');
            if (panel && panel.classList.contains('active')) {
                buildGraph(_currentType);
            }
        });

        // Rebuild when tab is clicked
        var graphTabBtn = document.getElementById('graphTabBtn');
        if (graphTabBtn) {
            graphTabBtn.addEventListener('click', function() {
                setTimeout(function() {
                    if (_graphData.length > 0) buildGraph(_currentType);
                    else showGraphEmpty(true);
                }, 80);
            });
        }

        // Initial empty
        showGraphEmpty(true);
    });

})();
