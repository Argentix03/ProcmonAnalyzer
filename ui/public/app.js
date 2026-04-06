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

    // Projects
    const projectSelect = document.getElementById('projectSelect');
    const newProjectBtn = document.getElementById('newProjectBtn');

    // State
    let dataHighConf = [];
    let dataCognitive = [];
    let savedApiKey = localStorage.getItem('gemini_api_key') || '';
    let tokensUsed = parseInt(localStorage.getItem('gemini_tokens_used')) || 0;

    // Fetch models if connected
    function loadModels(key) {
        if (!key) return;
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
                    if (m.id === 'gemini-1.5-flash' || m.id === 'gemini-2.0-flash-exp') opt.selected = true;
                    modelSelect.appendChild(opt);
                });
            } else {
                modelSelect.innerHTML = '<option>Failed to load models</option>';
            }
        }).catch(() => {
            modelSelect.innerHTML = '<option>Failed to load models</option>';
        });
    }

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
        if (isCsv) {
            loadingMsg.textContent = "Running Offline Analysis Engine...";
            progressContainer.classList.remove('hidden');
            progressBar.style.width = '0%';
            progressText.textContent = 'Initializing engine...';
            
            fetch('/api/upload', {
                method: 'POST',
                body: formData
            }).then(async res => {
                const reader = res.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let buffer = "";

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    buffer += decoder.decode(value, { stream: true });
                    let lines = buffer.split('\n');
                    buffer = lines.pop(); // keep last incomplete string in buffer

                    for (const line of lines) {
                        try {
                            const payload = JSON.parse(line.trim());
                            if (payload.type === 'progress') {
                                const pct = (payload.current / payload.total) * 100;
                                progressBar.style.width = pct + '%';
                                progressText.textContent = `Parsed ${payload.current.toLocaleString()} / ${payload.total.toLocaleString()} lines...`;
                            }
                            else if (payload.success) {
                                // Final payload received!
                                loadingOverlay.classList.add('hidden');
                                progressContainer.classList.add('hidden');
                                renderData(payload);
                            }
                            else if (payload.status) {
                                // Status event
                                progressText.textContent = payload.message;
                            }
                            else if (payload.error) {
                                loadingOverlay.classList.add('hidden');
                                alert("Error: " + payload.error);
                            }
                        } catch(e) {} // ignore split malforms
                    }
                }
                
                // Flush remaining buffer
                if (buffer.trim()) {
                    try {
                        const payload = JSON.parse(buffer.trim());
                        if (payload.success) {
                            loadingOverlay.classList.add('hidden');
                            progressContainer.classList.add('hidden');
                            renderData(payload);
                        } else if (payload.error) {
                            loadingOverlay.classList.add('hidden');
                            alert("Error: " + payload.error);
                        }
                    } catch(e) {}
                }
            }).catch(err => {
                loadingOverlay.classList.add('hidden');
                console.error(err);
                alert("Error processing upload");
            });

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
                alert("Error processing upload");
            });
        }
    }

    // Render Logic
    function renderData(apiData) {
        if (apiData.highConfidence) {
            dataHighConf = apiData.highConfidence;
        } else {
            dataHighConf = [];
        }

        if (apiData.cognitiveQueue) {
            dataCognitive = apiData.cognitiveQueue;
        } else {
            dataCognitive = [];
        }

        countHighConf.textContent = dataHighConf.length;
        countCognitive.textContent = dataCognitive.length;

        renderList(highConfList, dataHighConf, false);
        renderList(cognitiveList, dataCognitive, true);
    }

    function renderList(container, data, isCognitive) {
        container.innerHTML = '';
        if (!data || data.length === 0) {
            container.innerHTML = `<div class="empty-state">No leads available.</div>`;
            return;
        }

        // Limit to 200 items max for frontend performance
        const renderBlock = data.slice(0, 200);

        renderBlock.forEach((item, index) => {
            const div = document.createElement('div');
            // Give it an ID to update dynamically later
            div.className = 'lead-item';
            if (isCognitive) div.id = `cog-item-${index}`;
            
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
            (d.Type || "").toLowerCase().includes(query)
        );
        renderList(highConfList, filtered, false);
    });

    searchCognitive.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = dataCognitive.filter(d => 
            (d.Path || "").toLowerCase().includes(query) || 
            (d.Processes || "").toLowerCase().includes(query)
        );
        renderList(cognitiveList, filtered, true);
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
    triggerAIBtn.addEventListener('click', () => {
        if (!savedApiKey) {
            alert("You must configure your Gemini API Key in the settings first!");
            apiBtn.click();
            return;
        }

        const count = dataCognitive.length;
        if (count > 0) {
            warnCount.textContent = count.toLocaleString();
            // Estimating ~80 tokens per input blob and ~60 tokens per output.
            const estTokens = count * 140;
            warnTokens.textContent = "~ " + estTokens.toLocaleString();
            tokenWarnModal.classList.remove('hidden');
        }
    });

    document.getElementById('closeWarnModal').addEventListener('click', () => {
        tokenWarnModal.classList.add('hidden');
    });

    proceedAiBtn.addEventListener('click', async () => {
        tokenWarnModal.classList.add('hidden');
        triggerAIBtn.classList.add('hidden'); // hide while processing

        // Change UI of all cognitive elements to scanning
        const items = cognitiveList.querySelectorAll('.lead-item');
        items.forEach(el => {
            el.style.borderLeft = "3px solid var(--accent)";
            el.innerHTML = `<div class="spinner" style="width:14px; height:14px; margin:0; border-width:2px; display:inline-block;"></div> <span style="font-size:0.85rem; color:var(--text-muted);">Analyzing via Gemini...</span>`;
        });

        loadingMsg.textContent = "Establishing AI Data Stream...";
        // loadingOverlay.classList.remove('hidden'); // don't block the UI!

        try {
            const response = await fetch('/api/analyze-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    apiKey: savedApiKey, 
                    modelId: modelSelect.value,
                    queue: dataCognitive 
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
                                dataCognitive[domIndex] = resolvedItem; // override memory array
                                
                                // visually update the specific card in real-time
                                const targetDiv = document.getElementById('cog-item-' + domIndex);
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
                        } else if (payload.type === 'done') {
                            let oldTotal = parseInt(localStorage.getItem('gemini_tokens_used')) || 0;
                            let newTotal = oldTotal + payload.finalTokens;
                            localStorage.setItem('gemini_tokens_used', newTotal);
                            tokensUsedStat.textContent = newTotal.toLocaleString();
                            // renderList(cognitiveList, dataCognitive, true); // Optionally re-render flat array
                            triggerAIBtn.classList.remove('hidden');
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
