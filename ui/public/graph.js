// graph.js - Relationship Graph Explorer  v4
// Multi-field toggle system: Network, Matrix, Flow, Chord × 5 layouts
// Fields: Type, Processes, Severity, Integrity, Operation, PathFile, PathExt, PathDir

(function () {
    'use strict';

    var _graphData   = [];
    var _activeChart = null;
    var _simulation  = null;
    var _zoom        = null;
    var _currentType   = 'force';
    var _currentLayout = 'spring';

    // Field metadata: base color + display label
    var FIELD_META = {
        Type:      { color: '#5e6ad2', label: 'Finding Type' },
        Processes: { color: '#50fa7b', label: 'Process'       },
        Severity:  { color: '#f59f00', label: 'Severity'      },
        Integrity: { color: '#f03e3e', label: 'Integrity'     },
        Operation: { color: '#bd93f9', label: 'Operation'     },
        PathFile:  { color: '#ffb86c', label: 'Filename'      },
        PathExt:   { color: '#08bdbd', label: 'Extension'     },
        PathDir:   { color: '#ff79c6', label: 'Directory'     }
    };

    var SEV_COLOR   = { critical:'#f03e3e', high:'#f59f00', medium:'#5e6ad2', low:'#50fa7b', unknown:'#444860' };
    var INTEG_COLOR = { 'system':'#f03e3e','high':'#f59f00','medium plus':'#50fa7b','medium':'#5e6ad2','low':'#8be9fd','appcontainer':'#bd93f9','unknown':'#444860' };

    // Shared floating tooltip
    var _tooltip = null;
    function getTooltip() {
        if (!_tooltip) {
            _tooltip = document.createElement('div');
            _tooltip.style.cssText = 'position:fixed;background:rgba(15,17,26,0.96);border:1px solid rgba(94,106,210,0.5);border-radius:8px;padding:8px 12px;font-size:0.8rem;color:#e4e6eb;pointer-events:none;z-index:9999;display:none;max-width:240px;line-height:1.5;font-family:Inter,sans-serif;box-shadow:0 4px 20px rgba(0,0,0,0.5);';
            document.body.appendChild(_tooltip);
        }
        return _tooltip;
    }
    function showTooltip(html, x, y) { var t=getTooltip(); t.innerHTML=html; t.style.display='block'; t.style.left=(x+14)+'px'; t.style.top=(y-10)+'px'; }
    function hideTooltip() { getTooltip().style.display='none'; }

    // ── Get active field list from chip UI ────────────────────────────────────
    function getActiveFields() {
        var chips = document.querySelectorAll('#fieldChipRow .field-chip.active');
        return Array.from(chips).map(function(c){ return c.dataset.field; });
    }

    // ── Extract values for a field from one data item ─────────────────────────
    function getFieldValues(item, field) {
        if (field === 'Processes')
            return (item.Processes||'').split(',').map(function(p){ return p.trim().toLowerCase(); }).filter(Boolean);
        if (field === 'Severity') {
            var s = (item.Severity||'Unknown').trim(); return [s.charAt(0).toUpperCase()+s.slice(1)];
        }
        if (field === 'Integrity') return [(item.Integrity||'Unknown').trim()];
        if (field === 'Type')      return [(item.Type||'Unknown').trim()];
        if (field === 'Operation') return [(item.Operation||'Unknown').trim()];
        if (field === 'PathFile') {
            var p = (item.Path||'').replace(/\\/g,'/');
            var parts = p.split('/'); var fname = parts[parts.length-1]||'';
            return fname ? [fname.toLowerCase()] : ['unknown'];
        }
        if (field === 'PathExt') {
            var m = (item.Path||'').match(/\.([^.\\\/]+)$/i);
            return m ? ['.'+m[1].toLowerCase()] : ['(no ext)'];
        }
        if (field === 'PathDir') {
            var pp = (item.Path||'').replace(/\\/g,'/').split('/');
            pp.pop(); // remove filename
            // Take last 2 directory segments for readability
            var dir = pp.slice(-2).filter(Boolean).join('\\') || '(root)';
            return [dir.toLowerCase()];
        }
        return ['Unknown'];
    }

    // ── Color for a node ─────────────────────────────────────────────────────
    function getNodeColor(field, value) {
        if (field === 'Severity')  return SEV_COLOR[(value||'').toLowerCase()]  || FIELD_META.Severity.color;
        if (field === 'Integrity') return INTEG_COLOR[(value||'').toLowerCase()] || FIELD_META.Integrity.color;
        return (FIELD_META[field] || {color:'#5e6ad2'}).color;
    }

    // ── Multi-field graph data builder ────────────────────────────────────────
    // Returns { nodes, links, topByField, fieldCounts }
    // Nodes: { id: "Field::value", label, group(=field), count }
    // Links: edges between nodes from DIFFERENT fields that co-occur in same finding
    function buildMultiFieldGraph(data, fields, maxPerField) {
        if (fields.length === 0) return {nodes:[], links:[], topByField:{}, fieldCounts:{}};

        // Count values per field
        var fieldCounts = {}, topByField = {};
        fields.forEach(function(f) {
            fieldCounts[f] = {};
            data.forEach(function(item) {
                getFieldValues(item,f).forEach(function(v){ fieldCounts[f][v]=(fieldCounts[f][v]||0)+1; });
            });
            topByField[f] = Object.entries(fieldCounts[f])
                .sort(function(a,b){return b[1]-a[1];})
                .slice(0, maxPerField)
                .map(function(e){ return e[0]; });
        });

        // Build nodes
        var nodes=[], nodeById={};
        fields.forEach(function(f) {
            topByField[f].forEach(function(v) {
                var id=f+'::'+v;
                var n={id:id, label:v, group:f, count:fieldCounts[f][v]||0};
                nodes.push(n); nodeById[id]=n;
            });
        });

        // Build edges: co-occurrence across different fields
        var pairCounts={}, topSets={};
        fields.forEach(function(f){ topSets[f]=new Set(topByField[f]); });

        data.forEach(function(item) {
            var valsByField={};
            fields.forEach(function(f){ valsByField[f]=getFieldValues(item,f).filter(function(v){return topSets[f].has(v);}); });
            // All pairs of distinct fields
            for (var i=0; i<fields.length; i++) {
                for (var j=i+1; j<fields.length; j++) {
                    var fA=fields[i], fB=fields[j];
                    valsByField[fA].forEach(function(a) {
                        valsByField[fB].forEach(function(b) {
                            var idA=fA+'::'+a, idB=fB+'::'+b;
                            // Canonical key (smaller first to avoid duplicates)
                            var k=idA<idB ? idA+'|||'+idB : idB+'|||'+idA;
                            pairCounts[k]=(pairCounts[k]||0)+1;
                        });
                    });
                }
            }
        });

        var links=[];
        Object.entries(pairCounts).forEach(function(e) {
            var pts=e[0].split('|||');
            if (nodeById[pts[0]]&&nodeById[pts[1]]) links.push({source:pts[0],target:pts[1],value:e[1]});
        });

        return {nodes:nodes, links:links, topByField:topByField, fieldCounts:fieldCounts};
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LAYOUT ENGINES
    // ═══════════════════════════════════════════════════════════════════════

    function positionSpring(nodes) { nodes.forEach(function(n){ delete n.fx; delete n.fy; }); }

    function positionDot(nodes, W, H) {
        // Group by field, arrange each field as its own column
        var byField={};
        nodes.forEach(function(n){ (byField[n.group]=byField[n.group]||[]).push(n); });
        var fields=Object.keys(byField);
        var padX=60, padY=60;
        var usableW=W-padX*2, usableH=H-padY*2;
        var colStep=fields.length>1?usableW/(fields.length-1):0;
        fields.forEach(function(f,fi) {
            var arr=byField[f].sort(function(a,b){return b.count-a.count;});
            var x=padX+fi*colStep;
            var step=arr.length>1?usableH/(arr.length-1):0;
            arr.forEach(function(n,i){ n.fx=x; n.fy=padY+i*step; });
        });
    }

    function positionRadial(nodes, links, W, H) {
        var degree={};
        nodes.forEach(function(n){ degree[n.id]=0; });
        links.forEach(function(l){ var s=l.source.id||l.source,t=l.target.id||l.target; degree[s]=(degree[s]||0)+1; degree[t]=(degree[t]||0)+1; });
        var sorted=nodes.slice().sort(function(a,b){ return (degree[b.id]||0)-(degree[a.id]||0); });
        var adj={};
        nodes.forEach(function(n){ adj[n.id]=[]; });
        links.forEach(function(l){ var s=l.source.id||l.source,t=l.target.id||l.target; adj[s].push(t); adj[t].push(s); });
        var ring={}, visited=new Set(), queue=[sorted[0].id];
        visited.add(sorted[0].id); ring[sorted[0].id]=0;
        while (queue.length) { var cur=queue.shift(); (adj[cur]||[]).forEach(function(nb){ if(!visited.has(nb)){visited.add(nb);ring[nb]=ring[cur]+1;queue.push(nb);} }); }
        nodes.forEach(function(n,i){ if(ring[n.id]===undefined) ring[n.id]=(i%3)+1; });
        var rings={};
        nodes.forEach(function(n){ var r=ring[n.id]; (rings[r]=rings[r]||[]).push(n); });
        var cx=W/2, cy=H/2, maxRing=Math.max.apply(null,Object.keys(rings).map(Number))||1;
        var maxRadius=Math.min(W,H)*0.44, ringStep=maxRadius/maxRing;
        Object.keys(rings).forEach(function(r) {
            var arr=rings[r], ri=Number(r);
            if(ri===0){arr[0].fx=cx;arr[0].fy=cy;return;}
            var radius=ri*ringStep;
            arr.forEach(function(n,i){var a=(2*Math.PI*i/arr.length)-Math.PI/2; n.fx=cx+radius*Math.cos(a); n.fy=cy+radius*Math.sin(a);});
        });
    }

    function positionCirco(nodes, links, W, H) {
        var degree={};
        nodes.forEach(function(n){ degree[n.id]=0; });
        links.forEach(function(l){ var s=l.source.id||l.source,t=l.target.id||l.target; degree[s]=(degree[s]||0)+1; degree[t]=(degree[t]||0)+1; });
        // Sort field-by-field, each field's nodes grouped around the circle
        var byField={};
        nodes.forEach(function(n){ (byField[n.group]=byField[n.group]||[]).push(n); });
        var ordered=[];
        Object.keys(byField).forEach(function(f){ ordered=ordered.concat(byField[f].sort(function(a,b){return (degree[b.id]||0)-(degree[a.id]||0);})); });
        var cx=W/2, cy=H/2;
        var minRadius=(ordered.length*40)/(2*Math.PI);
        var radius=Math.max(minRadius,Math.min(W,H)*0.38);
        ordered.forEach(function(n,i){ var a=(2*Math.PI*i/ordered.length)-Math.PI/2; n.fx=cx+radius*Math.cos(a); n.fy=cy+radius*Math.sin(a); });
    }

    function positionGrid(nodes, W, H) {
        var sorted=nodes.slice().sort(function(a,b){ return b.count-a.count; });
        var n=sorted.length, cols=Math.ceil(Math.sqrt(n*(W/H)));
        var cellW=Math.max(100,(W-80)/Math.max(cols,1));
        var cellH=Math.max(90, (H-80)/Math.max(Math.ceil(n/cols),1));
        var totalW=(cols-1)*cellW, totalH=(Math.ceil(n/cols)-1)*cellH;
        var ox=(W-totalW)/2, oy=(H-totalH)/2;
        sorted.forEach(function(node,i){ node.fx=ox+(i%cols)*cellW; node.fy=oy+Math.floor(i/cols)*cellH; });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FORCE NETWORK
    // ═══════════════════════════════════════════════════════════════════════
    function buildForceGraph(data, fields, maxPerField, layout) {
        clearD3(); showSvg();
        var result = buildMultiFieldGraph(data, fields, maxPerField);
        var nodes=result.nodes, links=result.links;
        if (!nodes.length){ showGraphEmpty(true); return; }
        showGraphEmpty(false);

        var svg=d3.select('#graphSvg'), wrap=document.getElementById('graphCanvasWrap');
        var W=wrap.clientWidth||800, H=wrap.clientHeight||500;
        svg.attr('viewBox','0 0 '+W+' '+H);

        var g=svg.append('g').attr('class','graph-root');
        _zoom=d3.zoom().scaleExtent([0.05,8]).on('zoom',function(ev){g.attr('transform',ev.transform);});
        svg.call(_zoom);

        var isStatic=(layout!=='spring');
        if (layout==='dot')    positionDot(nodes,W,H);
        else if (layout==='radial') positionRadial(nodes,links,W,H);
        else if (layout==='circo')  positionCirco(nodes,links,W,H);
        else if (layout==='grid')   positionGrid(nodes,W,H);
        else                        positionSpring(nodes);

        var maxVal=Math.max.apply(null,links.map(function(l){return l.value;}))||1;
        var wScale=d3.scaleLinear().domain([1,maxVal]).range([1,7]);
        var maxCount=Math.max.apply(null,nodes.map(function(n){return n.count;}))||1;
        var rScale=d3.scaleSqrt().domain([1,maxCount]).range([8,28]);

        var useCurves=(layout==='circo');
        var linkSel;
        if (useCurves) {
            linkSel=g.append('g').attr('fill','none').selectAll('path').data(links).enter().append('path').attr('class','g-link')
                .attr('stroke',function(d){ return getEdgeColor(d,nodes); })
                .attr('stroke-width',function(d){return wScale(d.value);}).attr('stroke-opacity',0.38);
        } else {
            linkSel=g.append('g').attr('fill','none').selectAll('line').data(links).enter().append('line').attr('class','g-link')
                .attr('stroke',function(d){ return getEdgeColor(d,nodes); })
                .attr('stroke-width',function(d){return wScale(d.value);});
        }
        linkSel.on('mousemove',function(ev,d){
            var sn=nodeById(d.source,nodes), tn=nodeById(d.target,nodes);
            var sl=sn?sn.label:labelOf(d.source), tl=tn?tn.label:labelOf(d.target);
            showTooltip('<strong>'+sl+'</strong> ↔ <strong>'+tl+'</strong><br>Co-occurrences: <strong style="color:#50fa7b">'+d.value+'</strong>',ev.clientX,ev.clientY);
        }).on('mouseleave',hideTooltip);

        var nodeMap={};
        nodes.forEach(function(n){ nodeMap[n.id]=n; });

        var nodeSel=g.append('g').selectAll('.g-node').data(nodes).enter().append('g').attr('class','g-node')
            .call(d3.drag()
                .on('start',function(ev,d){ if(!ev.active&&_simulation) _simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
                .on('drag', function(ev,d){ d.fx=ev.x; d.fy=ev.y; })
                .on('end',  function(ev,d){ if(!ev.active&&_simulation) _simulation.alphaTarget(0); if(!isStatic){d.fx=null;d.fy=null;} })
            )
            .on('click',function(ev,d){ ev.stopPropagation(); highlightNode(d,nodeSel,linkSel); showInfoPanel(d,links,nodeMap); })
            .on('mousemove',function(ev,d){ showTooltip('<span style="color:'+getNodeColor(d.group,d.label)+'">●</span> <strong>'+d.label+'</strong><br>'+(FIELD_META[d.group]||{label:d.group}).label+' · Count: <strong style="color:#50fa7b">'+d.count.toLocaleString()+'</strong>',ev.clientX,ev.clientY); })
            .on('mouseleave',hideTooltip);

        nodeSel.append('circle')
            .attr('r',function(d){return rScale(d.count);})
            .attr('fill',function(d){return getNodeColor(d.group,d.label);})
            .attr('fill-opacity',0.85)
            .attr('stroke','#fff').attr('stroke-width',1.5).attr('stroke-opacity',0.2);

        // Label pill background
        nodeSel.append('rect').attr('class','g-label-bg').attr('rx',3).attr('ry',3)
            .attr('fill','rgba(12,14,22,0.75)')
            .attr('y',function(d){return rScale(d.count)+5;}).attr('height',14);

        nodeSel.append('text')
            .attr('dy',function(d){return rScale(d.count)+16;})
            .attr('text-anchor','middle').attr('font-size','10px').attr('font-family','Inter,sans-serif').attr('fill','#d0d4e0')
            .text(function(d){var l=d.label; return l.length>20?l.substring(0,20)+'…':l;});

        nodeSel.each(function(d){ var grp=d3.select(this),txt=grp.select('text').node(); if(!txt)return; var tw=txt.getComputedTextLength?txt.getComputedTextLength():60; grp.select('.g-label-bg').attr('x',-(tw/2+6)).attr('width',tw+12); });

        svg.on('click',function(){ nodeSel.classed('dimmed',false); linkSel.classed('dimmed',false).classed('highlighted',false); document.getElementById('graphInfoPanel').classList.add('hidden'); });

        function tick() {
            if (useCurves) {
                linkSel.attr('d',function(d){
                    var sx=d.source.x||0,sy=d.source.y||0,tx=d.target.x||0,ty=d.target.y||0;
                    var mx=(sx+tx)/2,my=(sy+ty)/2,dx=mx-W/2,dy=my-H/2,len=Math.sqrt(dx*dx+dy*dy)||1;
                    var bend=Math.min(80,Math.sqrt((sx-tx)*(sx-tx)+(sy-ty)*(sy-ty))*0.3);
                    return 'M'+sx+','+sy+' Q'+(mx-dy/len*bend)+','+(my+dx/len*bend)+' '+tx+','+ty;
                });
            } else {
                linkSel.attr('x1',function(d){return d.source.x;}).attr('y1',function(d){return d.source.y;})
                       .attr('x2',function(d){return d.target.x;}).attr('y2',function(d){return d.target.y;});
            }
            nodeSel.attr('transform',function(d){return 'translate('+(d.x||0)+','+(d.y||0)+')';});
        }

        if (isStatic) {
            _simulation=d3.forceSimulation(nodes)
                .force('link',d3.forceLink(links).id(function(d){return d.id;}).distance(5).strength(0.02))
                .force('collide',d3.forceCollide().radius(function(d){return rScale(d.count)+18;}).strength(0.6).iterations(3))
                .alphaDecay(0.05).on('tick',tick);
        } else {
            _simulation=d3.forceSimulation(nodes)
                .force('link',d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 120+160/(d.value+1);}).strength(0.5))
                .force('charge',d3.forceManyBody().strength(-600).distanceMax(600))
                .force('center',d3.forceCenter(W/2,H/2))
                .force('collide',d3.forceCollide().radius(function(d){return rScale(d.count)+30;}).strength(0.9).iterations(3))
                .velocityDecay(0.45).on('tick',tick);
        }
        buildMultiLegend(fields);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MATRIX – uses first 2 active fields
    // ═══════════════════════════════════════════════════════════════════════
    function buildMatrixGraph(data, fields, maxPerField) {
        clearD3(); showChartCanvas();
        if (fields.length < 2) { showGraphEmpty(true); showInfoMsg('Select at least 2 fields'); return; }
        var f0=fields[0], f1=fields[1];
        var result=buildMultiFieldGraph(data,[f0,f1],Math.min(maxPerField,20));
        var topSrc=result.topByField[f0]||[], topTgt=result.topByField[f1]||[];
        var pairs={};
        Object.entries(result.links.reduce(function(o,l){ var si=(l.source.id||l.source).replace(f0+'::',''), ti=(l.target.id||l.target).replace(f1+'::',''); var k=si+'||'+ti; o[k]=(o[k]||0)+l.value; return o; },{})).forEach(function(e){ pairs[e[0]]=e[1]; });
        if(!topSrc.length||!topTgt.length){showGraphEmpty(true);return;}
        showGraphEmpty(false);
        var maxVal=0; result.links.forEach(function(l){if(l.value>maxVal)maxVal=l.value;});
        var col0=FIELD_META[f0]||{color:'#5e6ad2'};
        var datasets=topSrc.map(function(src){
            return {label:src, data:topTgt.map(function(tgt){var v=pairs[src+'||'+tgt]||0;return {x:tgt,y:src,v:v,r:v>0?Math.max(4,(v/maxVal)*28):0};}),
                backgroundColor:getNodeColor(f0,src)+'cc', borderColor:getNodeColor(f0,src), borderWidth:1};
        });
        if(_activeChart){try{_activeChart.destroy();}catch(e){}}
        _activeChart=new Chart(document.getElementById('graphChartCanvas'),{
            type:'bubble', data:{datasets:datasets},
            options:{responsive:true,maintainAspectRatio:false,animation:{duration:500},parsing:false,
                scales:{x:{type:'category',labels:topTgt,title:{display:true,text:(FIELD_META[f1]||{label:f1}).label,color:'#a0a6b5',font:{size:11}},grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{size:10},maxRotation:40}},
                        y:{type:'category',labels:topSrc.slice().reverse(),title:{display:true,text:(FIELD_META[f0]||{label:f0}).label,color:'#a0a6b5',font:{size:11}},grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{size:10}}}},
                plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(15,17,26,0.96)',borderColor:'rgba(94,106,210,0.4)',borderWidth:1,callbacks:{label:function(ctx){var d=ctx.raw;return d.y+' → '+d.x+': '+d.v+' co-occurrences';}}}}}
        });
        document.getElementById('graphZoomBtns').classList.add('hidden');
        buildMultiLegend(fields);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FLOW – uses first 2 active fields as source (X) and breakdown (stacks)
    // ═══════════════════════════════════════════════════════════════════════
    function buildFlowGraph(data, fields, maxPerField) {
        clearD3(); showChartCanvas();
        if (fields.length < 2) { showGraphEmpty(true); showInfoMsg('Select at least 2 fields'); return; }
        var f0=fields[0], f1=fields[1];
        var result=buildMultiFieldGraph(data,[f0,f1],Math.min(maxPerField,16));
        var topSrc=result.topByField[f0]||[], topTgt=result.topByField[f1]||[];
        if(!topSrc.length){showGraphEmpty(true);return;}
        showGraphEmpty(false);
        // Rebuild pair counts indexed by (src, tgt)
        var pairs={};
        result.links.forEach(function(l){
            var sa=(l.source.id||l.source), ta=(l.target.id||l.target);
            var s=sa.startsWith(f0+'::')?sa.slice(f0.length+2):sa.slice(f1.length+2);
            var t=ta.startsWith(f1+'::')?ta.slice(f1.length+2):ta.slice(f0.length+2);
            var k=s+'||'+t; pairs[k]=(pairs[k]||0)+l.value;
        });
        var datasets=topTgt.map(function(tgt){
            return {label:tgt.length>20?tgt.substring(0,20)+'…':tgt, data:topSrc.map(function(src){return pairs[src+'||'+tgt]||0;}),
                backgroundColor:getNodeColor(f1,tgt), borderColor:'rgba(0,0,0,0.2)', borderWidth:1, borderRadius:3};
        });
        if(_activeChart){try{_activeChart.destroy();}catch(e){}}
        _activeChart=new Chart(document.getElementById('graphChartCanvas'),{
            type:'bar', data:{labels:topSrc.map(function(s){return s.length>20?s.substring(0,20)+'…':s;}), datasets:datasets},
            options:{responsive:true,maintainAspectRatio:false,animation:{duration:500},
                plugins:{legend:{position:'right',labels:{color:'#a0a6b5',font:{size:10},padding:10}},tooltip:{backgroundColor:'rgba(15,17,26,0.96)',borderColor:'rgba(94,106,210,0.4)',borderWidth:1}},
                scales:{x:{stacked:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#c4c8d4',font:{family:'monospace',size:9}},title:{display:true,text:(FIELD_META[f0]||{label:f0}).label,color:'#a0a6b5',font:{size:11}}},
                        y:{stacked:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#a0a6b5'},title:{display:true,text:'Count',color:'#a0a6b5',font:{size:11}}}}}
        });
        document.getElementById('graphZoomBtns').classList.add('hidden');
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHORD
    // ═══════════════════════════════════════════════════════════════════════
    function buildChordGraph(data, fields, maxPerField) {
        clearD3(); showSvg();
        var result=buildMultiFieldGraph(data,fields,Math.min(maxPerField,12));
        var nodes=result.nodes, links=result.links;
        if(nodes.length<2){showGraphEmpty(true);return;}
        showGraphEmpty(false);
        var allIds=nodes.map(function(n){return n.id;});
        var n=allIds.length, matrix=allIds.map(function(){return allIds.map(function(){return 0;});});
        links.forEach(function(l){
            var si=allIds.indexOf((l.source.id||l.source)), ti=allIds.indexOf((l.target.id||l.target));
            if(si>=0&&ti>=0){matrix[si][ti]+=l.value;matrix[ti][si]+=l.value;}
        });
        var svg=d3.select('#graphSvg'), wrap=document.getElementById('graphCanvasWrap');
        var W=wrap.clientWidth||800, H=wrap.clientHeight||500;
        var size=Math.min(W,H), outerR=size*0.42, innerR=outerR-22;
        svg.attr('viewBox','0 0 '+W+' '+H);
        var g=svg.append('g').attr('transform','translate('+W/2+','+H/2+')');
        _zoom=d3.zoom().scaleExtent([0.3,4]).on('zoom',function(ev){g.attr('transform','translate('+W/2+','+H/2+') scale('+ev.transform.k+')');});
        svg.call(_zoom);
        var chord=d3.chord().padAngle(0.04).sortSubgroups(d3.descending)(matrix);
        var arc=d3.arc().innerRadius(innerR).outerRadius(outerR);
        var ribbon=d3.ribbon().radius(innerR-2);
        g.append('g').selectAll('g').data(chord.groups).enter().append('g').each(function(d){
            var node=nodes[d.index];
            d3.select(this).append('path').attr('d',arc).attr('fill',getNodeColor(node.group,node.label)).attr('stroke','rgba(0,0,0,0.2)').attr('fill-opacity',0.9)
                .on('mousemove',function(ev){showTooltip('<strong>'+node.label+'</strong><br>'+(FIELD_META[node.group]||{label:node.group}).label+' · Total: '+d.value.toLocaleString(),ev.clientX,ev.clientY);}).on('mouseleave',hideTooltip);
            var angle=(d.startAngle+d.endAngle)/2, labelR=outerR+14;
            d3.select(this).append('text').attr('transform','rotate('+((angle*180/Math.PI)-90)+') translate('+labelR+',0)'+(angle>Math.PI?' rotate(180)':'')).attr('text-anchor',angle>Math.PI?'end':'start').attr('font-size','10px').attr('fill','#a0a6b5').text(function(){var l=node.label; return l.length>14?l.substring(0,14)+'…':l;});
        });
        g.append('g').attr('fill-opacity',0.5).selectAll('path').data(chord).enter().append('path').attr('class','g-chord').attr('d',ribbon)
            .attr('fill',function(d){return getNodeColor(nodes[d.source.index].group,nodes[d.source.index].label);}).attr('stroke','rgba(0,0,0,0.15)')
            .on('mousemove',function(ev,d){showTooltip('<strong>'+nodes[d.source.index].label+'</strong> ↔ <strong>'+nodes[d.target.index].label+'</strong><br>'+d.source.value.toLocaleString(),ev.clientX,ev.clientY);}).on('mouseleave',hideTooltip);
        buildMultiLegend(fields);
    }

    // ── Legend: one entry per active field ────────────────────────────────────
    function buildMultiLegend(fields) {
        var legend=document.getElementById('graphLegend'); if(!legend)return;
        legend.innerHTML='';
        fields.forEach(function(f) {
            var meta=FIELD_META[f]||{color:'#5e6ad2',label:f};
            var item=document.createElement('div'); item.className='graph-legend-item';
            var dot=document.createElement('div'); dot.className='graph-legend-dot'; dot.style.background=meta.color;
            var txt=document.createElement('span'); txt.textContent=meta.label;
            item.appendChild(dot); item.appendChild(txt); legend.appendChild(item);
        });
        legend.classList.remove('hidden');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    function labelOf(d) { var id=d.id||d; return id.split('::').slice(1).join('::') || id; }
    function nodeById(d,nodes) { var id=d.id||d; return nodes.find(function(n){return n.id===id;})||null; }
    function getEdgeColor(d,nodes) {
        var sn=nodeById(d.source,nodes); return sn?getNodeColor(sn.group,sn.label):'#5e6ad2';
    }
    function highlightNode(d,nodeSel,linkSel) {
        var connected=new Set([d.id]);
        linkSel.each(function(l){var s=l.source.id||l.source,t=l.target.id||l.target; if(s===d.id||t===d.id){connected.add(s);connected.add(t);}});
        nodeSel.classed('dimmed',function(n){return !connected.has(n.id);});
        linkSel.classed('dimmed',function(l){var s=l.source.id||l.source,t=l.target.id||l.target;return !(s===d.id||t===d.id);})
               .classed('highlighted',function(l){var s=l.source.id||l.source,t=l.target.id||l.target;return s===d.id||t===d.id;});
    }
    function showInfoPanel(d,links,nodeMap) {
        var panel=document.getElementById('graphInfoPanel'), title=document.getElementById('graphInfoTitle'), body=document.getElementById('graphInfoBody');
        title.textContent=d.label;
        var connections=links.filter(function(l){return (l.source.id||l.source)===d.id||(l.target.id||l.target)===d.id;});
        var html='<div class="graph-info-row"><span>Field</span><strong style="color:'+getNodeColor(d.group,d.label)+'">'+(FIELD_META[d.group]||{label:d.group}).label+'</strong></div>';
        html+='<div class="graph-info-row"><span>Appearances</span><strong>'+d.count.toLocaleString()+'</strong></div>';
        html+='<div class="graph-info-row"><span>Connections</span><strong>'+connections.length+'</strong></div>';
        var sorted=connections.slice().sort(function(a,b){return b.value-a.value;}).slice(0,6);
        if(sorted.length){
            html+='<hr style="border-color:rgba(255,255,255,0.06);margin:4px 0;">';
            html+='<div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.05em;color:#6a7090;margin-bottom:4px;">Top Partners</div>';
            sorted.forEach(function(l){
                var sa=l.source.id||l.source, ta=l.target.id||l.target;
                var partnerId=sa===d.id?ta:sa;
                var pn=nodeMap[partnerId]; var pl=pn?pn.label:labelOf(partnerId);
                var pc=pn?getNodeColor(pn.group,pn.label):'#a0a6b5';
                html+='<div class="graph-info-row"><span style="color:'+pc+'">'+( pl.length>18?pl.substring(0,18)+'…':pl)+'</span><strong>'+l.value+'</strong></div>';
            });
        }
        body.innerHTML=html; panel.classList.remove('hidden');
    }
    function showInfoMsg(msg) {
        var wrap=document.getElementById('graphCanvasWrap'); if(!wrap)return;
        d3.select('#graphSvg').selectAll('*').remove();
        d3.select('#graphSvg').append('text').attr('x',(wrap.clientWidth||800)/2).attr('y',(wrap.clientHeight||400)/2).attr('text-anchor','middle').attr('fill','#a0a6b5').attr('font-size','13px').attr('font-family','Inter,sans-serif').text(msg);
        showSvg(); showGraphEmpty(false);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DOM HELPERS
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
    function showSvg()         { document.getElementById('graphSvg').style.display='block'; document.getElementById('graphChartCanvas').classList.add('hidden'); }
    function showChartCanvas() { document.getElementById('graphSvg').style.display='none';  document.getElementById('graphChartCanvas').classList.remove('hidden'); }
    function showGraphEmpty(e) { var el=document.getElementById('graphEmpty'); if(el)el.style.display=e?'flex':'none'; document.getElementById('graphLoading').classList.add('hidden'); }
    function showLoading()     { document.getElementById('graphLoading').classList.remove('hidden'); }
    function updateLayoutPickerVisibility(type) {
        var grp=document.getElementById('layoutPickerGroup'), div=document.getElementById('layoutDivider'), show=(type==='force');
        if(grp)grp.style.display=show?'':'none'; if(div)div.style.display=show?'':'none';
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN DISPATCHER
    // ═══════════════════════════════════════════════════════════════════════
    function buildGraph(type, layout) {
        if(!_graphData||!_graphData.length){ showGraphEmpty(true); return; }
        var fields=getActiveFields();
        var maxPerField=parseInt(document.getElementById('graphMaxNodes').value)||30;
        layout=layout||_currentLayout;
        _currentType=type; _currentLayout=layout;
        updateLayoutPickerVisibility(type);
        if(fields.length<1){ showInfoMsg('Select at least one field to graph.'); return; }
        if(fields.length<2&&(type==='matrix'||type==='sankey')){ showInfoMsg('Select at least 2 fields for this mode.'); return; }
        showLoading();
        setTimeout(function(){
            try {
                if(type==='force')       buildForceGraph(_graphData,fields,maxPerField,layout);
                else if(type==='matrix') buildMatrixGraph(_graphData,fields,maxPerField);
                else if(type==='sankey') buildFlowGraph(_graphData,fields,maxPerField);
                else if(type==='chord')  buildChordGraph(_graphData,fields,maxPerField);
            } catch(e){ console.error('[Graph]',e); showGraphEmpty(true); }
            document.getElementById('graphLoading').classList.add('hidden');
        },60);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WIRE UP CONTROLS
    // ═══════════════════════════════════════════════════════════════════════
    document.addEventListener('DOMContentLoaded', function() {

        // Field chip toggles
        var chipRow=document.getElementById('fieldChipRow');
        if(chipRow) chipRow.addEventListener('click',function(e){
            var btn=e.target.closest('.field-chip'); if(!btn)return;
            var wasActive=btn.classList.contains('active');
            var activeCount=chipRow.querySelectorAll('.field-chip.active').length;
            if(wasActive&&activeCount<=1){return;} // keep at least 1
            btn.classList.toggle('active');
            buildGraph(_currentType,_currentLayout);
        });

        // Graph type picker
        var typePicker=document.getElementById('graphTypePicker');
        if(typePicker) typePicker.addEventListener('click',function(e){
            var btn=e.target.closest('.gtype-btn'); if(!btn)return;
            typePicker.querySelectorAll('.gtype-btn').forEach(function(b){b.classList.remove('active');});
            btn.classList.add('active');
            buildGraph(btn.dataset.type,_currentLayout);
        });

        // Layout picker
        var layoutPicker=document.getElementById('layoutPicker');
        if(layoutPicker) layoutPicker.addEventListener('click',function(e){
            var btn=e.target.closest('.layout-btn'); if(!btn)return;
            layoutPicker.querySelectorAll('.layout-btn').forEach(function(b){b.classList.remove('active');});
            btn.classList.add('active');
            buildGraph('force',btn.dataset.layout);
        });

        // Rebuild button
        document.getElementById('graphRefreshBtn').addEventListener('click',function(){ buildGraph(_currentType,_currentLayout); });

        // Max nodes slider
        var slider=document.getElementById('graphMaxNodes'), sliderVal=document.getElementById('graphMaxNodesVal');
        slider.addEventListener('input',function(){ if(sliderVal)sliderVal.textContent=slider.value; });
        slider.addEventListener('change',function(){ buildGraph(_currentType,_currentLayout); });

        // Zoom buttons
        document.getElementById('graphZoomIn').addEventListener('click',    function(){ if(_zoom)d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy,1.4); });
        document.getElementById('graphZoomOut').addEventListener('click',   function(){ if(_zoom)d3.select('#graphSvg').transition().duration(250).call(_zoom.scaleBy,0.7); });
        document.getElementById('graphZoomReset').addEventListener('click', function(){ if(_zoom)d3.select('#graphSvg').transition().duration(350).call(_zoom.transform,d3.zoomIdentity); });
        document.getElementById('graphInfoClose').addEventListener('click', function(){ document.getElementById('graphInfoPanel').classList.add('hidden'); });

        // Data events
        document.addEventListener('analyticsDataReady',function(e){
            _graphData=(e.detail.hc||[]).concat(e.detail.cog||[]);
            var panel=document.getElementById('graphPanel');
            if(panel&&panel.classList.contains('active')) buildGraph(_currentType,_currentLayout);
        });
        var graphTabBtn=document.getElementById('graphTabBtn');
        if(graphTabBtn) graphTabBtn.addEventListener('click',function(){ setTimeout(function(){ if(_graphData.length>0)buildGraph(_currentType,_currentLayout); else showGraphEmpty(true); },80); });

        showGraphEmpty(true);
    });

})();
