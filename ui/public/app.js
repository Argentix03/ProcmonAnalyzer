document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const loadingMsg = document.getElementById('loadingMsg');
    
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    
    const tabs = document.querySelectorAll('.tab');
    const panels = document.querySelectorAll('.list-panel');
    
    const highConfList = document.getElementById('highConfList');
    const cognitiveList = document.getElementById('cognitiveList');
    
    const countHighConf = document.getElementById('highConfCount');
    const countCognitive = document.getElementById('cognitiveCount');
    
    const searchHighConf = document.getElementById('searchHighConf');
    const searchCognitive = document.getElementById('searchCognitive');

    const modal = document.getElementById('detailsModal');
    const closeModal = document.getElementById('closeModal');

    // Report Management Elements
    const reportsList = document.getElementById('reportsList');
    const uploadReportBtn = document.getElementById('uploadReportBtn');
    const reportFileInput = document.getElementById('reportFileInput');

    // New AI Elements
    const apiBtn = document.getElementById('openSettingsBtn');
    const apiModal = document.getElementById('apiModal');
    const apiKeyInput = document.getElementById('apiKeyInput');
    const apiStatus = document.getElementById('apiStatus');
    const saveApiBtn = document.getElementById('saveApiBtn');
    const tokensUsedStat = document.getElementById('tokensUsedStat');
    const modelSelect = document.getElementById('modelSelect');

    const triggerAIBtn = document.getElementById('triggerAIBtn');
    const tokenWarnModal = document.getElementById('tokenWarnModal');
    const warnCount = document.getElementById('warnCount');
    const warnTokens = document.getElementById('warnTokens');
    const proceedAiBtn = document.getElementById('proceedAiBtn');

    // Script UI Elements
    const scriptModal = document.getElementById('scriptModal');
    const downloadScriptBtn = document.getElementById('downloadScriptBtn');
    const closeScriptModal = document.getElementById('closeScriptModal');

    if (downloadScriptBtn) {
        downloadScriptBtn.addEventListener('click', () => {
            scriptModal.classList.remove('hidden');
        });
    }

    if (closeScriptModal) {
        closeScriptModal.addEventListener('click', () => {
            scriptModal.classList.add('hidden');
        });
    }
    
    // Auto-close modal when clicking outside
    scriptModal.addEventListener('click', (e) => {
        if(e.target === scriptModal) scriptModal.classList.add('hidden');
    });

    // Global Info Elements
    const globalInfoModal = document.getElementById('globalInfoModal');
    const infoIconBtn = document.getElementById('infoIconBtn');
    const closeGlobalInfoModal = document.getElementById('closeGlobalInfoModal');

    if (infoIconBtn) {
        infoIconBtn.addEventListener('click', () => {
            globalInfoModal.classList.remove('hidden');
        });
    }

    if (closeGlobalInfoModal) {
        closeGlobalInfoModal.addEventListener('click', () => {
            globalInfoModal.classList.add('hidden');
        });
    }
    
    globalInfoModal.addEventListener('click', (e) => {
        if(e.target === globalInfoModal) globalInfoModal.classList.add('hidden');
    });

    // Projects
    const projectSelect = document.getElementById('projectSelect');
    const newProjectBtn = document.getElementById('newProjectBtn');

    // State
    let dataHighConf = [];
    let dataCognitive = [];
    let cognitiveView = [];
    let activeModalItem = null;
    let savedApiKey = localStorage.getItem('gemini_api_key') || '';
    let tokensUsed = parseInt(localStorage.getItem('gemini_tokens_used')) || 0;

    // Fetch models if connected
    function loadModels(key) {
        if (!key) return;
        
        const preferredModel = localStorage.getItem('gemini_selected_model');
        modelSelect.innerHTML = '<option>Loading models...</option>';
        fetch('/api/models', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ apiKey: key })
        }).then(r => r.json()).then(d => {
            if (d.success) {
                modelSelect.innerHTML = '';
                d.models.forEach(m => {
                    const opt = document.createElement('option');
                    opt.value = m.id; opt.textContent = m.name;
                    
                    if (preferredModel && m.id === preferredModel) {
                        opt.selected = true;
                    } else if (!preferredModel && (m.id === 'gemini-1.5-flash' || m.id === 'gemini-2.0-flash-exp')) {
                        opt.selected = true;
                    }
                    
                    modelSelect.appendChild(opt);
                });
            } else {
                modelSelect.innerHTML = '<option>Failed to load models</option>';
            }
        }).catch(() => {
            modelSelect.innerHTML = '<option>Failed to load models</option>';
        });
    }

    modelSelect.addEventListener('change', (e) => {
        localStorage.setItem('gemini_selected_model', e.target.value);
    });

    // Init Logic
    if (savedApiKey) {
        apiStatus.textContent = "Connected";
        apiStatus.style.color = "#50fa7b";
        loadModels(savedApiKey);
    }
    tokensUsedStat.textContent = tokensUsed.toLocaleString();

    // Fetch available projects
    function loadProjects() {
        return fetch('/api/projects')
            .then(res => res.json())
            .then(data => {
                if (data.success && data.projects) {
                    const currentVal = projectSelect.value;
                    projectSelect.innerHTML = '';
                    data.projects.forEach(p => {
                        const opt = document.createElement('option');
                        opt.value = p; opt.textContent = p;
                        projectSelect.appendChild(opt);
                    });
                    if (data.projects.includes(currentVal)) {
                        projectSelect.value = currentVal;
                    } else if (data.projects.length) {
                        projectSelect.value = data.projects[0];
                    }
                }
            });
    }

    // Auto-load data for project
    function loadProjectData() {
        fetch('/api/auto-inject', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ project: projectSelect.value })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) renderData(data);
            if (typeof loadReports === 'function') loadReports();
        });
    }

    loadProjects().then(loadProjectData);

    projectSelect.addEventListener('change', loadProjectData);

    newProjectBtn.addEventListener('click', () => {
        const name = prompt("Enter new workspace/project name:");
        if (name && name.trim() !== '') {
            fetch('/api/projects', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name: name.trim() })
            }).then(() => loadProjects()).then(() => {
                projectSelect.value = name.replace(/[^a-zA-Z0-9_-]/g, '_');
                loadProjectData();
            });
        }
    });

    const deleteProjectBtn = document.getElementById('deleteProjectBtn');
    if (deleteProjectBtn) {
        deleteProjectBtn.addEventListener('click', () => {
            const currentProj = projectSelect.value;
            if (currentProj.toLowerCase() === 'default_project') {
                return alert("The Default_Project workspace acts as the master fallback frame and cannot be permanently deleted.");
            }
            if (confirm(`Permanently destroy workspace '${currentProj}' and all its extracted leads / AI reports?`)) {
                fetch('/api/projects', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: currentProj })
                }).then(res => res.json()).then(data => {
                    if (data.success) {
                        loadProjects().then(() => loadProjectData());
                    } else if (data.error) {
                        alert("Error: " + data.error);
                    }
                });
            }
        });
    }

    // Tab Switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(tab.dataset.target).classList.add('active');
        });
    });

    // Drag and Drop Logic
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleFileUpload(e.target.files[0]);
    });

    function handleFileUpload(file) {
        const formData = new FormData();
        formData.append('reportFile', file);
        formData.append('project', projectSelect.value);

        const isCsv = file.name.toLowerCase().endsWith('.csv');
        const isPml = file.name.toLowerCase().endsWith('.pml');
        
        if (isPml) {
            prompt(
                "Sysinternals .PML binary traces must be converted to .CSV before analysis. Open Procmon (File -> Save As CSV), or run this terminal command:",
                `procmon.exe /AcceptEula /Quiet /OpenLog "${file.name}" /SaveAs "${file.name.replace('.pml', '.csv')}"`
            );
            return;
        }
        
        loadingOverlay.classList.remove('hidden');
        dropZone.classList.add('hidden'); // Hide drag box so loading UI natively slots into view
        if (isCsv) {
            loadingMsg.textContent = "Running Offline Analysis Engine...";
            progressContainer.classList.remove('hidden');
            progressBar.style.width = '0%';
            progressText.textContent = 'Initializing engine...';
            
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload', true);

            // 1. Physical Trace File Upload Progress
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = (e.loaded / e.total) * 100;
                    progressBar.style.width = pct + '%';
                    const mbLoaded = (e.loaded / (1024*1024)).toFixed(1);
                    const mbTotal  = (e.total / (1024*1024)).toFixed(1);
                    progressText.textContent = `Uploading Trace: ${mbLoaded} MB / ${mbTotal} MB...`;
                }
            };

            let buffer = "";
            let processedLength = 0;

            // 2. Server-Sent Events from NodeJS execution stream
            const processChunkStream = (isFinalFlush) => {
                const chunk = xhr.responseText.substring(processedLength);
                processedLength = xhr.responseText.length;
                
                buffer += chunk;
                let lines = buffer.split('\n');
                
                if (!isFinalFlush) {
                    buffer = lines.pop(); // keep last incomplete string in buffer if still streaming
                } else {
                    buffer = ""; // flush entirely
                }

                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const payload = JSON.parse(line.trim());
                        if (payload.type === 'progress') {
                            const pct = (payload.current / payload.total) * 100;
                            progressBar.style.width = pct + '%';
                            progressText.textContent = payload.label 
                                ? `${payload.label} ${payload.current.toLocaleString()} / ${payload.total.toLocaleString()}...`
                                : `Parsed ${payload.current.toLocaleString()} / ${payload.total.toLocaleString()} lines...`;
                        }
                        else if (payload.success) {
                            // Final payload received!
                            loadingOverlay.classList.add('hidden');
                            dropZone.classList.remove('hidden');
                            progressContainer.classList.add('hidden');
                            renderData(payload);
                        }
                        else if (payload.status) {
                            // Status event
                            progressText.textContent = payload.message;
                        }
                        else if (payload.error) {
                            loadingOverlay.classList.add('hidden');
                            dropZone.classList.remove('hidden');
                            alert("Error: " + payload.error);
                        }
                    } catch(e) {} // ignore split malforms
                }
            };

            xhr.onprogress = () => processChunkStream(false);
            xhr.onload     = () => processChunkStream(true);

            xhr.onerror = () => {
                loadingOverlay.classList.add('hidden');
                dropZone.classList.remove('hidden');
                alert("Error processing upload");
            };

            xhr.send(formData);

        } else {
            loadingMsg.textContent = "Injecting JSON Feed...";
            progressContainer.classList.add('hidden');
            
            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                loadingOverlay.classList.add('hidden');
                dropZone.classList.remove('hidden');
                if (data.error) return alert(data.error);
                if (data.isRawJson) {
                    if (data.data.length && data.data[0].DetailedReason) renderData({ highConfidence: data.data, cognitiveQueue: [] });
                    else if (data.data.length && data.data[0].Hint) renderData({ highConfidence: [], cognitiveQueue: data.data });
                } else if (data.success) {
                    renderData(data);
                }
            })
            .catch(err => {
                loadingOverlay.classList.add('hidden');
                dropZone.classList.remove('hidden');
                alert("Error processing upload");
            });
        }
    }

    // Render Logic
    function renderData(apiData) {
        if (apiData.highConfidence) {
            dataHighConf = apiData.highConfidence.map((item, index) => ({...item, OrigIdx: index, _isHighConf: true}));
        } else {
            dataHighConf = [];
        }

        if (apiData.cognitiveQueue) {
            dataCognitive = apiData.cognitiveQueue.map((item, index) => ({...item, OrigIdx: index}));
        } else {
            dataCognitive = [];
        }
        cognitiveView = [...dataCognitive];

        countHighConf.textContent = dataHighConf.length;
        countCognitive.textContent = dataCognitive.length;

        renderList(highConfList, dataHighConf, false);
        renderList(cognitiveList, dataCognitive, true);

        // Notify analytics panel
        document.dispatchEvent(new CustomEvent('analyticsDataReady', {
            detail: { hc: dataHighConf, cog: dataCognitive }
        }));
    }

    function renderList(container, data, isCognitive) {
        container.innerHTML = '';
        if (!data || data.length === 0) {
            container.innerHTML = `<div class="empty-state">No leads available.</div>`;
            return;
        }

        // Limit to 10000 items max for frontend performance (safely renders huge lists without truncating Gemini animation hooks)
        const renderBlock = data.slice(0, 10000);

        renderBlock.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'lead-item';
            if (isCognitive) {
                div.id = `cog-item-${item.OrigIdx}`;
            } else {
                div.id = `high-item-${item.OrigIdx}`;
            }
            
            const severityClass = item.Severity ? item.Severity.toLowerCase() : 'medium';
            const displaySeverity = isCognitive && item.Severity ? item.Severity : isCognitive ? 'Cognitive Target' : item.Severity;

            div.innerHTML = `
                <div class="badge ${severityClass}">${displaySeverity}</div>
                <div class="item-details">
                    <span class="item-type">${item.Type || 'Ambiguous Signature'}</span>
                    <span class="item-path">${item.Path}</span>
                </div>
            `;

            div.addEventListener('click', () => openModal(item, isCognitive));
            container.appendChild(div);
        });

        // Toggle AI button visibility
        if (isCognitive && data.length > 0) {
            triggerAIBtn.classList.remove('hidden');
        } else if (isCognitive) {
            triggerAIBtn.classList.add('hidden');
        }
    }

    // Modal Details
    function openModal(item, isCognitive) {
        document.getElementById('modalType').textContent = item.Type || 'Ambiguous Signature';
        
        const sevBadge = document.getElementById('modalSeverity');
        sevBadge.textContent = isCognitive ? 'AGENT REVIEW REQUIRED' : item.Severity;
        sevBadge.className = 'badge ' + (item.Severity ? item.Severity.toLowerCase() : 'medium');
        
        document.getElementById('modalPath').textContent = item.Path;
        
        const procsContainer = document.getElementById('modalProcesses');
        procsContainer.innerHTML = '';
        (item.Processes || "").split(',').forEach(p => {
            const trimmed = p.trim();
            if(trimmed) procsContainer.innerHTML += `<span class="process-tag">${trimmed}</span>`;
        });

        document.getElementById('modalReason').innerHTML = isCognitive 
            ? `<strong>Agent Hint:</strong> ${item.Hint}` 
            : `<strong>Rule Matched:</strong> ${item.DetailedReason}`;

        if (item.Timestamp || item.TraceFile || item.Operation) {
            document.getElementById('modalMetadataGroup').style.display = 'block';
            document.getElementById('modalTrace').textContent = item.TraceFile || 'N/A';
            document.getElementById('modalTime').textContent = item.Timestamp || 'N/A';
            document.getElementById('modalOp').textContent = (item.Operation || 'N/A') + (item.OperationDirection ? ' (' + item.OperationDirection + ')' : '');
            document.getElementById('modalResult').textContent = item.Result || 'N/A';
            document.getElementById('modalIntegrity').textContent = item.Integrity || 'Unknown';
            document.getElementById('modalDetail').textContent = item.Detail || 'None';
            
            // New exploit context fields
            var extraCtx = document.getElementById('modalExploitContext');
            if (extraCtx) {
                if (item.ExploitPrimitive || item.SqosLevel) {
                    extraCtx.style.display = 'block';
                    extraCtx.innerHTML = '';
                    if (item.ExploitPrimitive) extraCtx.innerHTML += '<div class="modal-row"><span>Exploit Primitive</span><strong>' + item.ExploitPrimitive + '</strong></div>';
                    if (item.SqosLevel) extraCtx.innerHTML += '<div class="modal-row"><span>SQOS Level</span><strong>' + item.SqosLevel + '</strong></div>';
                    if (item.OperationDirection) extraCtx.innerHTML += '<div class="modal-row"><span>Operation Direction</span><strong>' + item.OperationDirection + '</strong></div>';
                } else {
                    extraCtx.style.display = 'none';
                }
            }
        } else {
            document.getElementById('modalMetadataGroup').style.display = 'none';
        }

        const singleAnalyzeBtn = document.getElementById('singleAnalyzeBtn');
        if (
            (isCognitive && (!item.Severity || item.Severity === 'Cognitive Target' || !item.Severity.length)) ||
            (!isCognitive) 
        ) {
            singleAnalyzeBtn.classList.remove('hidden');
            activeModalItem = item;
        } else {
            singleAnalyzeBtn.classList.add('hidden');
            activeModalItem = null;
        }

        modal.classList.remove('hidden');
    }

    closeModal.addEventListener('click', () => modal.classList.add('hidden'));
    modal.addEventListener('click', (e) => {
        if(e.target === modal) modal.classList.add('hidden');
    });

    // Simple Search logic
    searchHighConf.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = dataHighConf.filter(d => 
            (d.Path || "").toLowerCase().includes(query) || 
            (d.Processes || "").toLowerCase().includes(query) ||
            (d.Type || "").toLowerCase().includes(query) ||
            (d.ExploitPrimitive || "").toLowerCase().includes(query)
        );
        renderList(highConfList, filtered, false);
    });

    const searchStatsCog = document.getElementById('searchStatsCog');
    const clearSearchCog = document.getElementById('clearSearchCog');

    searchCognitive.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        cognitiveView = dataCognitive.filter(d => 
            (d.Path || "").toLowerCase().includes(query) || 
            (d.Processes || "").toLowerCase().includes(query)
        );
        renderList(cognitiveList, cognitiveView, true);
        
        if (query.trim().length > 0) {
            searchStatsCog.style.display = 'inline';
            clearSearchCog.classList.remove('hidden');
            searchStatsCog.textContent = `Showing ${cognitiveView.length} / ${dataCognitive.length} Results`;
        } else {
            searchStatsCog.style.display = 'none';
            clearSearchCog.classList.add('hidden');
        }
    });

    clearSearchCog.addEventListener('click', () => {
        searchCognitive.value = '';
        cognitiveView = [...dataCognitive];
        renderList(cognitiveList, cognitiveView, true);
        searchStatsCog.style.display = 'none';
        clearSearchCog.classList.add('hidden');
    });

    // --- REPORTS MANAGEMENT ---
    function loadReports() {
        fetch('/api/reports', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ project: projectSelect.value })
        })
        .then(r => r.json())
        .then(data => {
            if (!data.success || data.reports.length === 0) {
                reportsList.innerHTML = '<div class="empty-state">No .md reports loaded for this workspace.</div>';
                return;
            }
            reportsList.innerHTML = '';
            data.reports.forEach(r => {
                const rcard = document.createElement('div');
                rcard.style.background = 'var(--bg-card)';
                rcard.style.padding = '15px';
                rcard.style.borderRadius = '8px';
                rcard.style.border = '1px solid var(--border)';
                
                const title = document.createElement('h4');
                title.textContent = r.file;
                title.style.margin = '0 0 12px 0';
                title.style.color = 'var(--text-main)';
                
                const findingsDiv = document.createElement('div');
                findingsDiv.style.display = 'flex';
                findingsDiv.style.flexDirection = 'column';
                findingsDiv.style.gap = '8px';
                
                r.findings.forEach(find => {
                    const frow = document.createElement('div');
                    frow.style.display = 'flex';
                    frow.style.alignItems = 'flex-start';
                    frow.style.gap = '10px';
                    frow.style.padding = '10px';
                    frow.style.borderRadius = '4px';
                    frow.style.background = find.checked ? 'rgba(80, 250, 123, 0.05)' : 'rgba(0,0,0,0.2)';
                    frow.style.borderLeft = find.checked ? '3px solid #50fa7b' : '3px solid var(--border)';
                    
                    const chk = document.createElement('input');
                    chk.type = 'checkbox';
                    chk.checked = find.checked;
                    chk.style.marginTop = '4px';
                    chk.style.cursor = 'pointer';
                    
                    const txtBlock = document.createElement('div');
                    const pMain = document.createElement('div');
                    pMain.style.fontWeight = '600';
                    pMain.style.fontSize = '0.9rem';
                    // Strip the raw markdown syntax so it renders gracefully
                    pMain.innerHTML = find.text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:3px;">$1</code>');
                    
                    const pSub = document.createElement('div');
                    pSub.style.fontSize = '0.8rem';
                    pSub.style.color = 'var(--text-muted)';
                    pSub.style.marginTop = '5px';
                    pSub.innerHTML = find.details.join('<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:3px;">$1</code>');
                    
                    txtBlock.appendChild(pMain);
                    if (find.details.length > 0) txtBlock.appendChild(pSub);
                    
                    chk.addEventListener('change', () => {
                       fetch('/api/toggle-report', {
                           method: 'POST',
                           headers: { 'Content-Type': 'application/json' },
                           body: JSON.stringify({
                               project: projectSelect.value,
                               file: r.file,
                               lineIndex: find.id,
                               checkState: chk.checked
                           })
                       }).then(() => loadReports());
                    });
                    
                    frow.appendChild(chk);
                    frow.appendChild(txtBlock);
                    findingsDiv.appendChild(frow);
                });
                
                rcard.appendChild(title);
                rcard.appendChild(findingsDiv);
                reportsList.appendChild(rcard);
            });
        });
    }

    uploadReportBtn.addEventListener('click', () => reportFileInput.click());
    reportFileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            const formData = new FormData();
            formData.append('reportFile', e.target.files[0]);
            formData.append('project', projectSelect.value);
            
            fetch('/api/upload-report', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(d => {
                if (d.success) loadReports();
                else alert(d.error);
            });
        }
    });

    // API MODALS & SAVING
    apiBtn.addEventListener('click', () => {
        apiKeyInput.value = savedApiKey;
        apiModal.classList.remove('hidden');
    });
    
    document.getElementById('closeApiModal').addEventListener('click', () => {
        apiModal.classList.add('hidden');
    });

    saveApiBtn.addEventListener('click', () => {
        const key = apiKeyInput.value.trim();
        if (key) {
            localStorage.setItem('gemini_api_key', key);
            savedApiKey = key;
            apiStatus.textContent = "Connected";
            apiStatus.style.color = "#50fa7b";
            loadModels(key);
        } else {
            localStorage.removeItem('gemini_api_key');
            savedApiKey = '';
            apiStatus.textContent = "Missing Key";
            apiStatus.style.color = "#f03e3e";
            modelSelect.innerHTML = '<option>Awaiting Valid Key</option>';
        }
        apiModal.classList.add('hidden');
    });

    // AI STREAMING ORCHESTRATION
    let aiAnalysisQueue = [];

    triggerAIBtn.addEventListener('click', () => {
        if (!savedApiKey) {
            alert("You must configure your Gemini API Key in the settings first!");
            document.getElementById('openSettingsBtn').click();
            return;
        }

        aiAnalysisQueue = [...cognitiveView]; // Use filtered items
        const count = aiAnalysisQueue.length;
        if (count > 0) {
            document.getElementById('warnCount').textContent = count.toLocaleString();
            
            const selEl = document.getElementById('modelSelect');
            const modelName = selEl.options[selEl.selectedIndex] ? selEl.options[selEl.selectedIndex].text : 'Gemini AI';
            document.getElementById('warnModelName').textContent = modelName;
            
            const estTokens = count * 140;
            document.getElementById('warnTokens').textContent = "~ " + estTokens.toLocaleString();
            document.getElementById('tokenWarnModal').classList.remove('hidden');
        }
    });

    document.getElementById('singleAnalyzeBtn').addEventListener('click', () => {
        if (!savedApiKey) {
            alert("You must configure your Gemini API Key in the settings first!");
            document.getElementById('openSettingsBtn').click();
            return;
        }
        if (activeModalItem) {
            aiAnalysisQueue = [activeModalItem];
            document.getElementById('detailsModal').classList.add('hidden');
            
            const selEl = document.getElementById('modelSelect');
            const modelName = selEl.options[selEl.selectedIndex] ? selEl.options[selEl.selectedIndex].text : 'Gemini AI';
            document.getElementById('warnModelName').textContent = modelName;
            
            document.getElementById('warnCount').textContent = "1";
            document.getElementById('warnTokens').textContent = "~ 140";
            document.getElementById('tokenWarnModal').classList.remove('hidden');
        }
    });

    document.getElementById('closeWarnModal').addEventListener('click', () => {
        document.getElementById('tokenWarnModal').classList.add('hidden');
    });

    document.getElementById('proceedAiBtn').addEventListener('click', async () => {
        document.getElementById('tokenWarnModal').classList.add('hidden');
        triggerAIBtn.classList.add('hidden'); // hide while processing

        // Change UI of all elements in the targeted queue to scanning
        aiAnalysisQueue.forEach(item => {
            const prefix = item._isHighConf ? 'high-item-' : 'cog-item-';
            const el = document.getElementById(prefix + item.OrigIdx);
            if (el) {
                el.style.borderLeft = "3px solid var(--accent)";
                el.innerHTML = `<div class="spinner" style="width:14px; height:14px; margin:0; border-width:2px; display:inline-block;"></div> <span style="font-size:0.85rem; color:var(--text-muted);">Analyzing via Gemini...</span>`;
            }
        });

        const loadingMsg = document.getElementById('loadingMsg');
        loadingMsg.textContent = "Establishing AI Data Stream...";

        try {
            const response = await fetch('/api/analyze-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    apiKey: savedApiKey, 
                    modelId: document.getElementById('modelSelect').value,
                    queue: aiAnalysisQueue 
                })
            });

            if (!response.ok) {
                 throw new Error("HTTP Status " + response.status);
            }

            // Object map to quickly find and mutate specific elements in array layout
            let domIndex = 0;

            const reader = response.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let buffer = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                let lines = buffer.split('\n\n');
                
                // Keep last incomplete chunk in buffer
                buffer = lines.pop();

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const payload = JSON.parse(line.substring(6));
                        
                        if (payload.type === 'chunk') {
                            
                            for (let i = 0; i < payload.items.length; i++) {
                                const resolvedItem = payload.items[i];
                                
                                // Guaranteed deterministic mapping back to original memory slot
                                const targetIdx = aiAnalysisQueue[domIndex].OrigIdx;
                                const isHighConfTarget = aiAnalysisQueue[domIndex]._isHighConf;
                                
                                resolvedItem.OrigIdx = targetIdx; 
                                resolvedItem._isHighConf = isHighConfTarget;
                                
                                let targetDiv;
                                if (isHighConfTarget) {
                                    dataHighConf[targetIdx] = resolvedItem; // override HighConf memory array
                                    targetDiv = document.getElementById('high-item-' + targetIdx);
                                } else {
                                    dataCognitive[targetIdx] = resolvedItem; // override Cognitive memory array
                                    targetDiv = document.getElementById('cog-item-' + targetIdx);
                                }
                                
                                // visually update the specific card in real-time
                                if (targetDiv) {
                                    targetDiv.style.background = "rgba(94, 106, 210, 0.1)";
                                    targetDiv.style.borderLeft = "3px solid #50fa7b";
                                    targetDiv.style.transform = "scale(1.02)";
                                    
                                    targetDiv.innerHTML = `
                                        <div class="badge" style="background:rgba(80, 250, 123, 0.2); color:#50fa7b; border:1px solid #50fa7b;">AI Analyzed</div>
                                        <div class="item-details">
                                            <span class="item-type" style="color:#fff;">${resolvedItem.Hint && resolvedItem.Hint.length > 60 ? resolvedItem.Hint.substring(0,60)+'...' : resolvedItem.Hint || 'Deduction logged'}</span>
                                            <span class="item-path">${resolvedItem.Path}</span>
                                        </div>
                                    `;
                                    // animate reset
                                    setTimeout(() => { targetDiv.style.transform = "scale(1)"; targetDiv.style.background = "var(--bg-card)"; }, 400);

                                    // Need to re-bind modal click so it shows the new resolution
                                    targetDiv.onclick = () => openModal(resolvedItem, true);
                                }
                                domIndex++;
                            }
                            
                            // Track Tokens natively!
                            let curTokens = parseInt(localStorage.getItem('gemini_tokens_used')) || 0;
                            curTokens += payload.currentTokensUsed; 
                        } else if (payload.type === 'error') {
                            console.error("Stream Error:", payload.message);
                            alert("AI Stream Error: " + payload.message + "\n\nPlease check DevTools console for raw details.");
                            const loadingMsg = document.getElementById('loadingMsg');
                            if(loadingMsg) loadingMsg.textContent = "Stream interrupted by API Error.";
                        } else if (payload.type === 'done') {
                            let oldTotal = parseInt(localStorage.getItem('gemini_tokens_used')) || 0;
                            let newTotal = oldTotal + payload.finalTokens;
                            localStorage.setItem('gemini_tokens_used', newTotal);
                            tokensUsedStat.textContent = newTotal.toLocaleString();
                            triggerAIBtn.classList.remove('hidden');
                            
                            // Synchronize newly analyzed state back to disk
                            fetch('/api/save-state', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    project: projectSelect.value,
                                    highConfidence: dataHighConf,
                                    cognitiveQueue: dataCognitive
                                })
                            }).catch(e => console.error("Could not persist AI response:", e));
                        }
                    }
                }
            }
        } catch(e) {
            loadingOverlay.classList.add('hidden');
            alert("Error streaming AI context: " + e.message);
            triggerAIBtn.classList.remove('hidden');
        }
    });

});
