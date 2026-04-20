// graph.js - Relationship Graph Explorer
// 4 graph types × 5 network layouts (Spring, Layered/dot, Radial/twopi, Circular/circo, Grid/sfdp)

(function () {
    'use strict';

    var _graphData   = [];
    var _activeChart = null;
    var _simulation  = null;
    var _zoom        = null;
    var _currentType   = 'force';
    var _currentLayout = 'spring';
    var _selectedNode  = null;

    var COLORS = [
        '#5e6ad2','#50fa7b','#f59f00','#f03e3e','#bd93f9',
        '#ffb86c','#08bdbd','#ff79c6','#44b8cc','#62d196',
        '#ff6464','#82c8ff','#ffdc50','#c882ff','#ffa050',
        '#5ef0a0','#f08040','#40c0ff','#ff50a0','#a0ff50'
    ];
    var SEV_COLOR   = { critical:'#f03e3e', high:'#f59f00', medium:'#5e6ad2', low:'#50fa7b', unknown:'#444860' };
    var INTEG_COLOR = { 'system':'#f03e3e','high':'#f59f00','medium plus':'#50fa7b','medium':'#5e6ad2','low':'#8be9fd','appcontainer':'#bd93f9','unknown':'#444860' };

    // ── Shared floating tooltip ──────────────────────────────────────────────
    var _tooltip = null;
    function getTooltip() {
        if (!_tooltip) {
            _tooltip = document.createElement('div');
            _tooltip.style.cssText = 'position:fixed;background:rgba(15,17,26,0.96);border:1px solid rgba(94,106,210,0.5);border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#e4e6eb;pointer-events:none;z-index:9999;display:none;max-width:240px;line-height:1.5;font-family:Inter,sans-serif;box-shadow:0 4px 20px rgba(0,0,0,0.5);';
            document.body.appendChild(_tooltip);
        }
        return _tooltip;
    }
    function showTooltip(html, x, y) {
        var t = getTooltip(); t.innerHTML = html; t.style.display = 'block';
        t.style.left = (x + 14) + 'px'; t.style.top = (y - 10) + 'px';
    }
    function hideTooltip() { getTooltip().style.display = 'none'; }

    // ── Field value extractor ────────────────────────────────────────────────
    function getFieldValues(item, field) {
        if (field === 'Processes')
            return (item.Processes || '').split(',').map(function(p){ return p.trim().toLowerCase(); }).filter(Boolean);
        if (field === 'Severity')  { var s = (item.Severity||'Unknown').trim(); return [s.charAt(0).toUpperCase()+s.slice(1)]; }
        if (field === 'Integrity') return [(item.Integrity||'Unknown').trim()];
        if (field === 'Type')      return [(item.Type||'Unknown').trim()];
        if (field === 'Operation') return [(item.Operation||'Unknown').trim()];
        return ['Unknown'];
    }

    // ── Build source↔target occurrence map ──────────────────────────────────
    function buildPairMap(data, srcField, tgtField, maxSrc, maxTgt) {
        var srcCount = {}, tgtCount = {};
        data.forEach(function(item) {
            getFieldValues(item, srcField).forEach(function(v){ srcCount[v] = (srcCount[v]||0)+1; });
            getFieldValues(item, tgtField).forEach(function(v){ tgtCount[v] = (tgtCount[v]||0)+1; });
        });
        var topSrc = Object.entries(srcCount).sort(function(a,b){return b[1]-a[1];}).slice(0,maxSrc).map(function(e){return e[0];});
        var topTgt = Object.entries(tgtCount).sort(function(a,b){return b[1]-a[1];}).slice(0,maxTgt).map(function(e){return e[0];});
        var topSrcSet = new Set(topSrc), topTgtSet = new Set(topTgt);
        var pairs = {};
        data.forEach(function(item) {
            var srcs = getFieldValues(item, srcField).filter(function(v){return topSrcSet.has(v);});
            var tgts = getFieldValues(item, tgtField).filter(function(v){return topTgtSet.has(v);});
            srcs.forEach(function(s){ tgts.forEach(function(t){ if(s!==t){ var k=s+'||'+t; pairs[k]=(pairs[k]||0)+1; } }); });
        });
        return { pairs:pairs, topSrc:topSrc, topTgt:topTgt, srcCount:srcCount, tgtCount:tgtCount };
    }

    // ── Color helpers ────────────────────────────────────────────────────────
    function colorForValue(field, value) {
        var v = value.toLowerCase();
        if (field === 'Severity')  return SEV_COLOR[v]   || null;
        if (field === 'Integrity') return INTEG_COLOR[v] || null;
        return null;
    }
    function makeColorMap(values, field) {
        var map = {};
        values.forEach(function(v,i){ map[v] = colorForValue(field,v) || COLORS[i%COLORS.length]; });
        return map;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LAYOUT ENGINES  (return { nodes, links } with x/y pre-set where fixed)
    // ═══════════════════════════════════════════════════════════════════════

    // 1. Spring – full D3 force sim (neato / fdp)
    function positionSpring(nodes) {
        nodes.forEach(function(n){ delete n.fx; delete n.fy; });
    }

    // 2. Dot – bipartite layered columns, spread across full canvas height
    function positionDot(nodes, W, H) {
        var srcs = nodes.filter(function(n){ return n.group==='src'; }).sort(function(a,b){return b.count-a.count;});
        var tgts = nodes.filter(function(n){ return n.group==='tgt'; }).sort(function(a,b){return b.count-a.count;});
        var padTop = 60, padBot = 60;
        function column(arr, x) {
            if (!arr.length) return;
            var usable = H - padTop - padBot;
            var step = arr.length > 1 ? usable / (arr.length - 1) : 0;
            arr.forEach(function(n, i){ n.fx = x; n.fy = padTop + i * step; });
        }
        column(srcs, W * 0.15);
        column(tgts, W * 0.85);
    }

    // 3. Radial / Twopi – hub-and-spoke, rings sized to fill canvas
    function positionRadial(nodes, links, W, H) {
        var degree = {};
        nodes.forEach(function(n){ degree[n.id]=0; });
        links.forEach(function(l){
            var s=l.source.id||l.source, t=l.target.id||l.target;
            degree[s]=(degree[s]||0)+1; degree[t]=(degree[t]||0)+1;
        });
        var sorted = nodes.slice().sort(function(a,b){ return (degree[b.id]||0)-(degree[a.id]||0); });
        var adj = {};
        nodes.forEach(function(n){ adj[n.id]=[]; });
        links.forEach(function(l){
            var s=l.source.id||l.source, t=l.target.id||l.target;
            adj[s].push(t); adj[t].push(s);
        });
        var ring={}, visited=new Set(), queue=[sorted[0].id];
        visited.add(sorted[0].id); ring[sorted[0].id]=0;
        while (queue.length) {
            var cur=queue.shift();
            (adj[cur]||[]).forEach(function(nb){ if(!visited.has(nb)){visited.add(nb);ring[nb]=ring[cur]+1;queue.push(nb);} });
        }
        nodes.forEach(function(n,i){ if(ring[n.id]===undefined) ring[n.id]=(i%3)+1; });
        var rings={};
        nodes.forEach(function(n){ var r=ring[n.id]; (rings[r]=rings[r]||[]).push(n); });
        var cx=W/2, cy=H/2;
        var maxRing=Math.max.apply(null, Object.keys(rings).map(Number)) || 1;
        // Use 42% of the smaller dimension per ring so all rings fit comfortably
        var maxRadius = Math.min(W, H) * 0.44;
        var ringStep  = maxRadius / maxRing;
        Object.keys(rings).forEach(function(r) {
            var arr=rings[r], ri=Number(r);
            if (ri===0) { arr[0].fx=cx; arr[0].fy=cy; return; }
            var radius = ri * ringStep;
            arr.forEach(function(n,i){ var a=(2*Math.PI*i/arr.length)-Math.PI/2; n.fx=cx+radius*Math.cos(a); n.fy=cy+radius*Math.sin(a); });
        });
    }

    // 4. Circo – nodes evenly on a circle with label-safe radius
    function positionCirco(nodes, links, W, H) {
        var degree={};
        nodes.forEach(function(n){ degree[n.id]=0; });
        links.forEach(function(l){
            var s=l.source.id||l.source, t=l.target.id||l.target;
            degree[s]=(degree[s]||0)+1; degree[t]=(degree[t]||0)+1;
        });
        var srcs=nodes.filter(function(n){return n.group==='src';}).sort(function(a,b){return (degree[b.id]||0)-(degree[a.id]||0);});
        var tgts=nodes.filter(function(n){return n.group==='tgt';}).sort(function(a,b){return (degree[b.id]||0)-(degree[a.id]||0);});
        var ordered=srcs.concat(tgts);
        var cx=W/2, cy=H/2;
        // Ensure enough arc-length between nodes: at least 40px between centres on circle
        var minRadius = (ordered.length * 40) / (2 * Math.PI);
        var radius = Math.max(minRadius, Math.min(W, H) * 0.38);
        ordered.forEach(function(n,i){ var a=(2*Math.PI*i/ordered.length)-Math.PI/2; n.fx=cx+radius*Math.cos(a); n.fy=cy+radius*Math.sin(a); });
    }

    // 5. Grid – sorted by count, cells sized so nodes don't overlap
    function positionGrid(nodes, W, H) {
        var sorted=nodes.slice().sort(function(a,b){ return b.count-a.count; });
        var n=sorted.length;
        var cols=Math.ceil(Math.sqrt(n*(W/H)));
        var rows=Math.ceil(n/cols);
        // Minimum cell size to prevent overlap (60px padding around largest node)
        var cellW=Math.max(100, (W-80)/Math.max(cols,1));
        var cellH=Math.max(90,  (H-80)/Math.max(rows,1));
        var totalW=(cols-1)*cellW, totalH=(rows-1)*cellH;
        var ox=(W-totalW)/2, oy=(H-totalH)/2;
        sorted.forEach(function(node,i){ node.fx=ox+(i%cols)*cellW; node.fy=oy+Math.floor(i/cols)*cellH; });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FORCE GRAPH (Network mode)
    // ═══════════════════════════════════════════════════════════════════════
    function buildForceGraph(data, srcField, tgtField, maxNodes, layout) {
        clearD3(); showSvg();
        layout = layout || 'spring';

        var maxEach = Math.ceil(maxNodes/2);
        var result  = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var pairs = result.pairs, topSrc = result.topSrc, topTgt = result.topTgt;
        var srcCount = result.srcCount, tgtCount = result.tgtCount;

        // Build node list
        var nodeMap = {};
        topSrc.forEach(function(v){ nodeMap[v+'::src']={ id:v+'::src', label:v, group:'src', count:srcCount[v]||0 }; });
        topTgt.forEach(function(v){ if(!nodeMap[v+'::src']) nodeMap[v+'::tgt']={ id:v+'::tgt', label:v, group:'tgt', count:tgtCount[v]||0 }; });
        var nodes = Object.values(nodeMap);
        var nodeById = {};
        nodes.forEach(function(n){ nodeById[n.id]=n; });

        // Build edge list
        var links = [];
        Object.entries(pairs).forEach(function(e) {
            var pts=e[0].split('||'), s=pts[0], t=pts[1], w=e[1];
            var srcId=s+'::src', tgtId=(nodeById[t+'::src']?t+'::src':t+'::tgt');
            if(nodeById[srcId]&&nodeById[tgtId]) links.push({source:srcId,target:tgtId,value:w});
        });

        if(nodes.length===0){ showGraphEmpty(true); return; }
        showGraphEmpty(false);

        var srcColorMap = makeColorMap(topSrc, srcField);
        var tgtColorMap = makeColorMap(topTgt, tgtField);

        var svg  = d3.select('#graphSvg');
        var wrap = document.getElementById('graphCanvasWrap');
        var W    = wrap.clientWidth  || 800;
        var H    = wrap.clientHeight || 500;
        svg.attr('viewBox','0 0 '+W+' '+H);

        // ── Arrow marker defs ──
        var defs = svg.append('defs');
        defs.append('marker')
            .attr('id','arrow').attr('viewBox','0 0 10 10')
            .attr('refX',10).attr('refY',5)
            .attr('markerWidth',6).attr('markerHeight',6)
            .attr('orient','auto')
          .append('path').attr('d','M 0 0 L 10 5 L 0 10 z')
            .attr('fill','rgba(94,106,210,0.4)');

        var g = svg.append('g').attr('class','graph-root');

        _zoom = d3.zoom().scaleExtent([0.08,6]).on('zoom',function(ev){ g.attr('transform',ev.transform); });
        svg.call(_zoom);

        // ── Pre-position nodes for chosen layout ──
        var isStaticLayout = (layout !== 'spring');
        if (layout === 'dot')    positionDot(nodes, W, H);
        else if (layout === 'radial') positionRadial(nodes, links, W, H);
        else if (layout === 'circo')  positionCirco(nodes, links, W, H);
        else if (layout === 'grid')   positionGrid(nodes, W, H);
        else                           positionSpring(nodes);

        // ── Link width / opacity scale ──
        var maxVal = Math.max.apply(null, links.map(function(l){return l.value;})) || 1;
        var wScale = d3.scaleLinear().domain([1,maxVal]).range([1,7]);

        // ── Draw links ──
        var useCurves = (layout==='circo');  // curved edges look better on circular layout
        var linkSel;
        if (useCurves) {
            linkSel = g.append('g').attr('fill','none').selectAll('path')
                .data(links).enter().append('path')
                .attr('class','g-link')
                .attr('stroke', function(d){ return nodeColor(d.source, srcColorMap, tgtColorMap); })
                .attr('stroke-width', function(d){ return wScale(d.value); })
                .attr('stroke-opacity', 0.38);
        } else {
            linkSel = g.append('g').attr('fill','none').selectAll('line')
                .data(links).enter().append('line')
                .attr('class','g-link')
                .attr('stroke', function(d){ return nodeColor(d.source, srcColorMap, tgtColorMap); })
                .attr('stroke-width', function(d){ return wScale(d.value); });
        }

        linkSel.on('mousemove', function(ev,d){
            var s=labelOf(d.source), t=labelOf(d.target);
            showTooltip('<strong>'+s+'</strong> → <strong>'+t+'</strong><br>Co-occurrences: <strong style="color:#50fa7b">'+d.value+'</strong>', ev.clientX, ev.clientY);
        }).on('mouseleave', hideTooltip);

        // ── Radius scale ──
        var maxCount = Math.max.apply(null, nodes.map(function(n){return n.count;})) || 1;
        var rScale   = d3.scaleSqrt().domain([1,maxCount]).range([8,28]);

        // ── Draw nodes ──
        var nodeSel = g.append('g').selectAll('.g-node')
            .data(nodes).enter().append('g').attr('class','g-node')
            .call(d3.drag()
                .on('start', function(ev,d){ if(!ev.active&&_simulation) _simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
                .on('drag',  function(ev,d){ d.fx=ev.x; d.fy=ev.y; })
                .on('end',   function(ev,d){ if(!ev.active&&_simulation) _simulation.alphaTarget(0); if(!isStaticLayout){d.fx=null;d.fy=null;} })
            )
            .on('click', function(ev,d){ ev.stopPropagation(); highlightNode(d,nodeSel,linkSel,srcColorMap,tgtColorMap); showInfoPanel(d,srcField,tgtField,links); })
            .on('mousemove', function(ev,d){ showTooltip('<strong>'+d.label+'</strong><br>'+d.group.toUpperCase()+' · Count: <strong style="color:#50fa7b">'+d.count.toLocaleString()+'</strong>', ev.clientX, ev.clientY); })
            .on('mouseleave', hideTooltip);

        nodeSel.append('circle')
            .attr('r', function(d){ return rScale(d.count); })
            .attr('fill', function(d){ return (d.group==='src'?srcColorMap:tgtColorMap)[d.label] || '#5e6ad2'; })
            .attr('fill-opacity', 0.88)
            .attr('stroke','#fff').attr('stroke-width',1.5).attr('stroke-opacity',0.25);

        // Label pill background for readability
        nodeSel.append('rect')
            .attr('class','g-label-bg')
            .attr('rx', 3).attr('ry', 3)
            .attr('fill','rgba(12,14,22,0.72)')
            .attr('y', function(d){ return rScale(d.count)+5; })
            .attr('height', 14);

        var labelText = nodeSel.append('text')
            .attr('dy', function(d){ return rScale(d.count)+16; })
            .attr('text-anchor','middle')
            .attr('font-size','10px')
            .attr('font-family','Inter,sans-serif')
            .attr('fill','#d0d4e0')
            .text(function(d){ var l=d.label; return l.length>20?l.substring(0,20)+'…':l; });

        // Size the pill bg after text is in DOM
        nodeSel.each(function(d) {
            var grp = d3.select(this);
            var txt = grp.select('text').node();
            if (!txt) return;
            var tw = txt.getComputedTextLength ? txt.getComputedTextLength() : 60;
            var pad = 6;
            grp.select('.g-label-bg')
                .attr('x', -(tw/2+pad))
                .attr('width', tw + pad*2);
        });

        svg.on('click', function(){
            _selectedNode=null;
            nodeSel.classed('dimmed',false);
            linkSel.classed('dimmed',false).classed('highlighted',false);
            document.getElementById('graphInfoPanel').classList.add('hidden');
        });

        // ── Layout-specific tick function ──
        function tick() {
            if (useCurves) {
                linkSel.attr('d', function(d) {
                    var sx=d.source.x||0, sy=d.source.y||0, tx=d.target.x||0, ty=d.target.y||0;
                    var cx=W/2, cy=H/2;
                    var mx=(sx+tx)/2, my=(sy+ty)/2;
                    var dx=mx-cx, dy=my-cy;
                    var len=Math.sqrt(dx*dx+dy*dy)||1;
                    var bend=Math.min(80, Math.sqrt((sx-tx)*(sx-tx)+(sy-ty)*(sy-ty))*0.3);
                    var cpx=mx-dy/len*bend, cpy=my+dx/len*bend;
                    return 'M'+sx+','+sy+' Q'+cpx+','+cpy+' '+tx+','+ty;
                });
            } else {
                linkSel.attr('x1',function(d){return d.source.x;}).attr('y1',function(d){return d.source.y;})
                       .attr('x2',function(d){return d.target.x;}).attr('y2',function(d){return d.target.y;});
            }
            nodeSel.attr('transform',function(d){return 'translate('+(d.x||0)+','+(d.y||0)+')';});
        }

        // ── D3 simulation ──────────────────────────────────────────────────
        // Spring: strong repulsion, long link distances, free nodes.
        // Static layouts: nodes are hard-fixed (fx/fy kept); sim only handles
        // collision nudging and link rendering — NO charge or center forces
        // that would collapse nodes.
        if (isStaticLayout) {
            _simulation = d3.forceSimulation(nodes)
                .force('link',    d3.forceLink(links).id(function(d){return d.id;}).distance(5).strength(0.02))
                .force('collide', d3.forceCollide().radius(function(d){return rScale(d.count)+18;}).strength(0.6).iterations(3))
                .alphaDecay(0.05)
                .on('tick', tick);
        } else {
            _simulation = d3.forceSimulation(nodes)
                .force('link',    d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 120+160/(d.value+1);}).strength(0.5))
                .force('charge',  d3.forceManyBody().strength(-600).distanceMax(600))
                .force('center',  d3.forceCenter(W/2, H/2))
                .force('collide', d3.forceCollide().radius(function(d){return rScale(d.count)+30;}).strength(0.9).iterations(3))
                .velocityDecay(0.45)
                .on('tick', tick);
        }

        // ── Legend ──
        buildLegend(topSrc,srcField,srcColorMap,topTgt,tgtField,tgtColorMap);
    }

    function labelOf(d) { return (d.label || (d.id||d).replace('::src','').replace('::tgt','')); }
    function nodeColor(d, srcCM, tgtCM) {
        var id = d.id||d; var g = id.endsWith('::src')?'src':'tgt';
        var lbl = id.replace('::src','').replace('::tgt','');
        return (g==='src'?srcCM:tgtCM)[lbl] || '#5e6ad2';
    }

    function highlightNode(d, nodeSel, linkSel, srcColorMap, tgtColorMap) {
        var connected = new Set([d.id]);
        linkSel.each(function(l){ var s=l.source.id||l.source, t=l.target.id||l.target; if(s===d.id||t===d.id){connected.add(s);connected.add(t);} });
        nodeSel.classed('dimmed', function(n){ return !connected.has(n.id); });
        linkSel.classed('dimmed', function(l){ var s=l.source.id||l.source,t=l.target.id||l.target; return !(s===d.id||t===d.id); })
               .classed('highlighted', function(l){ var s=l.source.id||l.source,t=l.target.id||l.target; return s===d.id||t===d.id; });
    }

    function showInfoPanel(d, srcField, tgtField, links) {
        var panel=document.getElementById('graphInfoPanel'), title=document.getElementById('graphInfoTitle'), body=document.getElementById('graphInfoBody');
        title.textContent = d.label;
        var connections = links.filter(function(l){ return (l.source.id||l.source)===d.id||(l.target.id||l.target)===d.id; });
        var html = '<div class="graph-info-row"><span>Field</span><strong>'+(d.group==='src'?srcField:tgtField)+'</strong></div>';
        html += '<div class="graph-info-row"><span>Appearances</span><strong>'+d.count.toLocaleString()+'</strong></div>';
        html += '<div class="graph-info-row"><span>Connections</span><strong>'+connections.length+'</strong></div>';
        var sorted = connections.slice().sort(function(a,b){return b.value-a.value;}).slice(0,6);
        if (sorted.length) {
            html += '<hr style="border-color:rgba(255,255,255,0.06);margin:4px 0;">';
            html += '<div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.05em;color:#6a7090;margin-bottom:4px;">Top Partners</div>';
            sorted.forEach(function(l){
                var s=(l.source.id||l.source).replace('::src','').replace('::tgt','');
                var t=(l.target.id||l.target).replace('::src','').replace('::tgt','');
                var p=s===d.label?t:s;
                html += '<div class="graph-info-row"><span>'+(p.length>16?p.substring(0,16)+'…':p)+'</span><strong>'+l.value+'</strong></div>';
            });
        }
        body.innerHTML = html;
        panel.classList.remove('hidden');
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MATRIX (bubble heat-map)
    // ═══════════════════════════════════════════════════════════════════════
    function buildMatrixGraph(data, srcField, tgtField, maxNodes) {
        clearD3(); showChartCanvas();
        var maxEach = Math.min(maxNodes, 20);
        var result  = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var topSrc=result.topSrc, topTgt=result.topTgt, pairs=result.pairs;
        if(!topSrc.length||!topTgt.length){ showGraphEmpty(true); return; }
        showGraphEmpty(false);
        var maxVal=0; Object.values(pairs).forEach(function(v){if(v>maxVal)maxVal=v;});
        var srcColorMap = makeColorMap(topSrc, srcField);
        var datasets = topSrc.map(function(src,si){
            return { label:src, data:topTgt.map(function(tgt){ var v=pairs[src+'||'+tgt]||0; return {x:tgt,y:src,v:v,r:v>0?Math.max(4,(v/maxVal)*28):0}; }),
                backgroundColor:(srcColorMap[src]||COLORS[si%COLORS.length]).replace('rgb(','rgba(').replace(')',',0.75)'),
                borderColor:srcColorMap[src]||COLORS[si%COLORS.length], borderWidth:1 };
        });
        if(_activeChart){try{_activeChart.destroy();}catch(e){}} 
        _activeChart = new Chart(document.getElementById('graphChartCanvas'),{
            type:'bubble', data:{datasets:datasets},
            options:{ responsive:true, maintainAspectRatio:false, animation:{duration:500}, parsing:false,
                scales:{ x:{type:'category',labels:topTgt,title:{display:true,text:tgtField,color:'#a0a6b5',font:{size:11}},grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{size:10},maxRotation:40}},
                         y:{type:'category',labels:topSrc.slice().reverse(),title:{display:true,text:srcField,color:'#a0a6b5',font:{size:11}},grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{size:10}}} },
                plugins:{ legend:{display:false}, tooltip:{backgroundColor:'rgba(15,17,26,0.96)',borderColor:'rgba(94,106,210,0.4)',borderWidth:1,callbacks:{label:function(ctx){var d=ctx.raw;return d.y+' → '+d.x+': '+d.v+' co-occurrences';}}}} }
        });
        buildLegend(topSrc,srcField,srcColorMap,null,null,null);
        document.getElementById('graphZoomBtns').classList.add('hidden');
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FLOW (stacked bar)
    // ═══════════════════════════════════════════════════════════════════════
    function buildFlowGraph(data, srcField, tgtField, maxNodes) {
        clearD3(); showChartCanvas();
        var maxSrc  = Math.min(maxNodes, 16);
        var result  = buildPairMap(data, srcField, tgtField, maxSrc, 20);
        var topSrc=result.topSrc, topTgt=result.topTgt, pairs=result.pairs;
        if(!topSrc.length){ showGraphEmpty(true); return; }
        showGraphEmpty(false);
        var tgtColorMap = makeColorMap(topTgt, tgtField);
        var datasets = topTgt.map(function(tgt,ti){
            return { label:tgt, data:topSrc.map(function(src){return pairs[src+'||'+tgt]||0;}),
                backgroundColor:tgtColorMap[tgt]||COLORS[ti%COLORS.length], borderColor:'rgba(0,0,0,0.2)', borderWidth:1, borderRadius:3 };
        });
        if(_activeChart){try{_activeChart.destroy();}catch(e){}}
        _activeChart = new Chart(document.getElementById('graphChartCanvas'),{
            type:'bar', data:{ labels:topSrc.map(function(s){return s.length>20?s.substring(0,20)+'…':s;}), datasets:datasets },
            options:{ responsive:true, maintainAspectRatio:false, animation:{duration:500},
                plugins:{ legend:{position:'right',labels:{color:'#a0a6b5',font:{size:10},padding:10}}, tooltip:{backgroundColor:'rgba(15,17,26,0.96)',borderColor:'rgba(94,106,210,0.4)',borderWidth:1} },
                scales:{ x:{stacked:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{family:'monospace',size:9}},title:{display:true,text:srcField,color:'#a0a6b5',font:{size:11}}},
                         y:{stacked:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#a0a6b5'},title:{display:true,text:'Count',color:'#a0a6b5',font:{size:11}}} } }
        });
        document.getElementById('graphZoomBtns').classList.add('hidden');
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHORD diagram
    // ═══════════════════════════════════════════════════════════════════════
    function buildChordGraph(data, srcField, tgtField, maxNodes) {
        clearD3(); showSvg();
        var maxEach = Math.min(Math.ceil(maxNodes/2),12);
        var result  = buildPairMap(data, srcField, tgtField, maxEach, maxEach);
        var allKeys = result.topSrc.slice();
        result.topTgt.forEach(function(k){if(allKeys.indexOf(k)<0)allKeys.push(k);});
        allKeys = allKeys.slice(0, maxNodes);
        if(allKeys.length<2){showGraphEmpty(true);return;}
        showGraphEmpty(false);
        var n=allKeys.length, matrix=allKeys.map(function(){return allKeys.map(function(){return 0;});});
        Object.entries(result.pairs).forEach(function(e){ var p=e[0].split('||'),si=allKeys.indexOf(p[0]),ti=allKeys.indexOf(p[1]); if(si>=0&&ti>=0){matrix[si][ti]+=e[1];matrix[ti][si]+=e[1];} });
        var svg=d3.select('#graphSvg'), wrap=document.getElementById('graphCanvasWrap');
        var W=wrap.clientWidth||800, H=wrap.clientHeight||500;
        var size=Math.min(W,H), outerR=size*0.42, innerR=outerR-22;
        svg.attr('viewBox','0 0 '+W+' '+H);
        var g=svg.append('g').attr('transform','translate('+W/2+','+H/2+')');
        _zoom=d3.zoom().scaleExtent([0.3,4]).on('zoom',function(ev){g.attr('transform','translate('+W/2+','+H/2+') scale('+ev.transform.k+')');});
        svg.call(_zoom);
        var colorMap=makeColorMap(allKeys,srcField);
        var chord=d3.chord().padAngle(0.04).sortSubgroups(d3.descending)(matrix);
        var arc=d3.arc().innerRadius(innerR).outerRadius(outerR);
        var ribbon=d3.ribbon().radius(innerR-2);
        g.append('g').selectAll('g').data(chord.groups).enter().append('g').each(function(d){
            d3.select(this).append('path').attr('d',arc).attr('fill',colorMap[allKeys[d.index]]||COLORS[d.index%COLORS.length]).attr('stroke','rgba(0,0,0,0.2)').attr('fill-opacity',0.9)
                .on('mousemove',function(ev){showTooltip('<strong>'+allKeys[d.index]+'</strong><br>Total flow: '+d.value.toLocaleString(),ev.clientX,ev.clientY);}).on('mouseleave',hideTooltip);
            var angle=(d.startAngle+d.endAngle)/2, labelR=outerR+14;
            d3.select(this).append('text').attr('transform','rotate('+(((angle*180/Math.PI)-90))+') translate('+labelR+',0)'+(angle>Math.PI?' rotate(180)':'')).attr('text-anchor',angle>Math.PI?'end':'start').attr('font-size','10px').attr('fill','#a0a6b5').text(function(){var l=allKeys[d.index];return l.length>14?l.substring(0,14)+'…':l;});
        });
        g.append('g').attr('fill-opacity',0.55).selectAll('path').data(chord).enter().append('path').attr('class','g-chord').attr('d',ribbon).attr('fill',function(d){return colorMap[allKeys[d.source.index]]||COLORS[d.source.index%COLORS.length];}).attr('stroke','rgba(0,0,0,0.15)')
            .on('mousemove',function(ev,d){showTooltip('<strong>'+allKeys[d.source.index]+'</strong> ↔ <strong>'+allKeys[d.target.index]+'</strong><br>Strength: '+d.source.value.toLocaleString(),ev.clientX,ev.clientY);}).on('mouseleave',hideTooltip);
        buildLegend(allKeys,srcField,colorMap,null,null,null);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LEGEND
    // ═══════════════════════════════════════════════════════════════════════
    function buildLegend(srcKeys, srcField, srcColorMap, tgtKeys, tgtField, tgtColorMap) {
        var legend=document.getElementById('graphLegend'); if(!legend)return;
        legend.innerHTML='';
        function addItems(keys,colorMap,label){
            if(!keys||!keys.length)return;
            if(label){var sep=document.createElement('span');sep.style.cssText='font-size:0.7rem;text-transform:uppercase;letter-spacing:0.06em;color:#555a70;font-weight:700;align-self:center;';sep.textContent=label+':';legend.appendChild(sep);}
            keys.slice(0,12).forEach(function(k){var item=document.createElement('div');item.className='graph-legend-item';var dot=document.createElement('div');dot.className='graph-legend-dot';dot.style.background=colorMap[k]||'#5e6ad2';var txt=document.createElement('span');txt.textContent=k.length>22?k.substring(0,22)+'…':k;item.appendChild(dot);item.appendChild(txt);legend.appendChild(item);});
        }
        if(tgtKeys&&tgtField){addItems(srcKeys,srcColorMap,srcField);addItems(tgtKeys,tgtColorMap,tgtField);}
        else{addItems(srcKeys,srcColorMap,'');}
        legend.classList.remove('hidden');
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DOM helpers
    // ═══════════════════════════════════════════════════════════════════════
    function clearD3() {
        if(_simulation){_simulation.stop();_simulation=null;}
        d3.select('#graphSvg').selectAll('*').remove();
        if(_activeChart){try{_activeChart.destroy();}catch(e){}}_activeChart=null;
        document.getElementById('graphInfoPanel').classList.add('hidden');
        document.getElementById('graphLegend').classList.add('hidden');
        document.getElementById('graphLegend').innerHTML='';
        document.getElementById('graphZoomBtns').classList.remove('hidden');
        hideTooltip();
    }
    function showSvg()         { document.getElementById('graphSvg').style.display='block';  document.getElementById('graphChartCanvas').classList.add('hidden'); }
    function showChartCanvas() { document.getElementById('graphSvg').style.display='none';   document.getElementById('graphChartCanvas').classList.remove('hidden'); }
    function showGraphEmpty(e) { var el=document.getElementById('graphEmpty'); if(el)el.style.display=e?'flex':'none'; document.getElementById('graphLoading').classList.add('hidden'); }
    function showLoading()     { document.getElementById('graphLoading').classList.remove('hidden'); }

    // ── Show/hide layout picker based on graph type ──
    function updateLayoutPickerVisibility(type) {
        var grp = document.getElementById('layoutPickerGroup');
        var div = document.getElementById('layoutDivider');
        var show = (type === 'force');
        if (grp) grp.style.display = show ? '' : 'none';
        if (div) div.style.display = show ? '' : 'none';
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN DISPATCHER
    // ═══════════════════════════════════════════════════════════════════════
    function buildGraph(type, layout) {
        var data = _graphData;
        if(!data||!data.length){ showGraphEmpty(true); return; }
        var srcField  = document.getElementById('graphSourceField').value;
        var tgtField  = document.getElementById('graphTargetField').value;
        var maxNodes  = parseInt(document.getElementById('graphMaxNodes').value)||30;
        layout = layout || _currentLayout;
        _currentType   = type;
        _currentLayout = layout;
        updateLayoutPickerVisibility(type);
        if(srcField===tgtField){
            clearD3(); showSvg(); showGraphEmpty(false);
            d3.select('#graphSvg').append('text').attr('x',(document.getElementById('graphCanvasWrap').clientWidth||800)/2).attr('y',(document.getElementById('graphCanvasWrap').clientHeight||400)/2).attr('text-anchor','middle').attr('fill','#a0a6b5').attr('font-size','14px').attr('font-family','Inter,sans-serif').text('Source and Target fields must be different.');
            return;
        }
        showLoading();
        setTimeout(function(){
            try {
                if(type==='force')       buildForceGraph(data,srcField,tgtField,maxNodes,layout);
                else if(type==='matrix') buildMatrixGraph(data,srcField,tgtField,maxNodes);
                else if(type==='sankey') buildFlowGraph(data,srcField,tgtField,maxNodes);
                else if(type==='chord')  buildChordGraph(data,srcField,tgtField,maxNodes);
            } catch(e){ console.error('[Graph]',e); showGraphEmpty(true); }
            document.getElementById('graphLoading').classList.add('hidden');
        }, 60);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WIRE UP CONTROLS
    // ═══════════════════════════════════════════════════════════════════════
    document.addEventListener('DOMContentLoaded', function() {

        // Graph type picker
        var typePicker = document.getElementById('graphTypePicker');
        if(typePicker) typePicker.addEventListener('click', function(e){
            var btn = e.target.closest('.gtype-btn'); if(!btn)return;
            typePicker.querySelectorAll('.gtype-btn').forEach(function(b){b.classList.remove('active');});
            btn.classList.add('active');
            buildGraph(btn.dataset.type, _currentLayout);
        });

        // Layout picker (network only)
        var layoutPicker = document.getElementById('layoutPicker');
        if(layoutPicker) layoutPicker.addEventListener('click', function(e){
            var btn = e.target.closest('.layout-btn'); if(!btn)return;
            layoutPicker.querySelectorAll('.layout-btn').forEach(function(b){b.classList.remove('active');});
            btn.classList.add('active');
            buildGraph('force', btn.dataset.layout);
        });

        // Rebuild button
        var refreshBtn = document.getElementById('graphRefreshBtn');
        if(refreshBtn) refreshBtn.addEventListener('click', function(){ buildGraph(_currentType, _currentLayout); });

        // Max nodes slider
        var slider = document.getElementById('graphMaxNodes'), sliderVal = document.getElementById('graphMaxNodesVal');
        if(slider) {
            slider.addEventListener('input', function(){ if(sliderVal) sliderVal.textContent=slider.value; });
            slider.addEventListener('change', function(){ buildGraph(_currentType, _currentLayout); });
        }

        // Zoom buttons
        document.getElementById('graphZoomIn').addEventListener('click',    function(){ if(_zoom) d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy,1.4); });
        document.getElementById('graphZoomOut').addEventListener('click',   function(){ if(_zoom) d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy,0.7); });
        document.getElementById('graphZoomReset').addEventListener('click', function(){ if(_zoom) d3.select('#graphSvg').transition().duration(350).call(_zoom.transform,d3.zoomIdentity); });

        // Info panel close
        document.getElementById('graphInfoClose').addEventListener('click', function(){ document.getElementById('graphInfoPanel').classList.add('hidden'); });

        // Data event
        document.addEventListener('analyticsDataReady', function(e){
            _graphData = (e.detail.hc||[]).concat(e.detail.cog||[]);
            var panel = document.getElementById('graphPanel');
            if(panel&&panel.classList.contains('active')) buildGraph(_currentType, _currentLayout);
        });

        // Tab click
        var graphTabBtn = document.getElementById('graphTabBtn');
        if(graphTabBtn) graphTabBtn.addEventListener('click', function(){
            setTimeout(function(){ if(_graphData.length>0) buildGraph(_currentType,_currentLayout); else showGraphEmpty(true); }, 80);
        });

        showGraphEmpty(true);
    });

})();
