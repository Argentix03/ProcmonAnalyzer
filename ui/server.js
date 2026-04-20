const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const port = 3000;

// Setup directories
const ROOT_DIR = path.resolve(__dirname, '..');
const UPLOAD_DIR = path.join(ROOT_DIR, 'ui_uploads');
const PROJECTS_DIR = path.join(ROOT_DIR, 'projects');

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
if (!fs.existsSync(PROJECTS_DIR)) {
    fs.mkdirSync(PROJECTS_DIR, { recursive: true });
}

// Multer config for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `upload_${Date.now()}_${file.originalname}`)
});
const upload = multer({ storage });

// Serve static UI files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '50mb' }));

// Helper to reliably read JSON as an array
const readSafeJson = (filePath) => {
    try {
        if (fs.existsSync(filePath)) {
            const raw = fs.readFileSync(filePath, 'utf8');
            const cleanRaw = raw.replace(/^\uFEFF/, '').trim();

            // If the file was just created as a 0-byte physical shell, return safely
            if (!cleanRaw) return [];

            let parsed = JSON.parse(cleanRaw);

            // Force PowerShell JSON outputs to remain arrays when they only have 1 item
            if (!Array.isArray(parsed)) {
                if (parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
                    parsed = [parsed];
                } else {
                    parsed = [];
                }
            }
            return parsed;
        }
    } catch (e) {
        console.error(`Error reading ${filePath}:`, e);
    }
    return [];
};

// API: List Projects
app.get('/api/projects', (req, res) => {
    try {
        const folders = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true })
            .filter(dirent => dirent.isDirectory())
            .map(dirent => dirent.name);
        res.json({ success: true, projects: folders });
    } catch (e) {
        res.json({ success: false, projects: [] });
    }
});

// API: Create Project
app.post('/api/projects', (req, res) => {
    let { name } = req.body;
    if (!name) return res.status(400).json({ error: "Name required" });
    name = name.replace(/[^a-zA-Z0-9_-]/g, '_'); // safe dir name

    const projPath = path.join(PROJECTS_DIR, name);
    if (!fs.existsSync(projPath)) fs.mkdirSync(projPath, { recursive: true });

    res.json({ success: true, project: name });
});
// API: Delete Project
app.delete('/api/projects', (req, res) => {
    let { name } = req.body;
    if (!name) return res.status(400).json({ error: "Name required" });
    name = name.replace(/[^a-zA-Z0-9_-]/g, '_');

    // Prevent deleting fundamental default framework
    if (name.toLowerCase() === 'default_project') {
        return res.status(400).json({ error: "Cannot delete Default_Project" });
    }

    const projPath = path.join(PROJECTS_DIR, name);
    if (fs.existsSync(projPath)) {
        fs.rmSync(projPath, { recursive: true, force: true });
    }
    res.json({ success: true });
});
// API: Auto-inject existing JSONs from a project
app.post('/api/auto-inject', (req, res) => {
    let { project } = req.body;
    if (!project) project = 'Default_Project';

    const projPath = path.join(PROJECTS_DIR, project);
    const highConf = readSafeJson(path.join(projPath, 'high_confidence_leads.json'));
    const cognitive = readSafeJson(path.join(projPath, 'cognitive_review_queue.json'));

    res.json({
        success: true,
        highConfidence: highConf,
        cognitiveQueue: cognitive
    });
});

// API: Process File Upload (JSON or CSV)
app.post('/api/upload', upload.single('reportFile'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const ext = path.extname(req.file.originalname).toLowerCase();

    // Identify output project immediately
    let activeProject = req.body.project || 'Default_Project';
    const projPath = path.join(PROJECTS_DIR, activeProject);
    if (!fs.existsSync(projPath)) fs.mkdirSync(projPath, { recursive: true });

    // If it's pure JSON, merge it into the active project to persist state
    if (ext === '.json') {
        const data = readSafeJson(req.file.path);

        let hcPath = path.join(projPath, 'high_confidence_leads.json');
        let cgPath = path.join(projPath, 'cognitive_review_queue.json');

        const existingHc = readSafeJson(hcPath);
        const existingCg = readSafeJson(cgPath);

        let hcUpdated = false;
        let cgUpdated = false;

        if (data.length > 0) {
            // Deduce the schema to route it to the correct queue
            if (data[0].DetailedReason) {
                const merged = [...data, ...existingHc];
                fs.writeFileSync(hcPath, JSON.stringify(merged, null, 4));
                hcUpdated = true;
            } else if (data[0].Hint) {
                const merged = [...data, ...existingCg];
                fs.writeFileSync(cgPath, JSON.stringify(merged, null, 4));
                cgUpdated = true;
            } else {
                // If the user drops raw unanalyzed properties json, we skip for safety
                console.log("[!] Unknown JSON schema uploaded.");
            }
        }

        fs.unlinkSync(req.file.path); // Cleanup the raw incoming dump

        return res.json({
            success: true,
            isRawJson: false, // Fakes a standard pipeline response to the UI
            highConfidence: hcUpdated ? readSafeJson(hcPath) : existingHc,
            cognitiveQueue: cgUpdated ? readSafeJson(cgPath) : existingCg
        });
    }



    // If it's a CSV, we run the massive pipeline!
    if (ext === '.csv') {
        const csvPath = req.file.path;
        console.log(`[+] Received CSV ProcMon payload routing to Project: ${activeProject}`);

        const parseScript = path.join(ROOT_DIR, 'skills', 'Parse-ProcmonWriteables', 'scripts', 'ParseProcmonTraceTestWritablePaths.ps1');
        const analyzeScript = path.join(ROOT_DIR, 'skills', 'Analyze-ExecutionLeads', 'scripts', 'AnalyzeExecutionLeads.ps1');

        // Prevent OS/Express buffering so chunks immediately flush to the UI
        res.setHeader('Content-Type', 'application/x-ndjson');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders();

        res.write(JSON.stringify({ status: "streaming", message: "Starting powershell sequence..." }) + "\n");

        // 1. Run Parser
        const psParse = spawn('powershell.exe', [
            '-ExecutionPolicy', 'Bypass',
            '-File', parseScript,
            '-CsvPath', csvPath,
            '-OutputPath', projPath,
            '-Silent'
        ], { cwd: ROOT_DIR });

        let parserBuffer = "";
        psParse.stdout.on('data', (data) => {
            parserBuffer += data.toString();
            let lines = parserBuffer.split('\n');
            parserBuffer = lines.pop();

            for (let str of lines) {
                const match = str.match(/\[PROGRESS\] (\d+)\s*\/\s*(\d+)(?:\s+(.+))?/);
                if (match) {
                    const payloadOut = JSON.stringify({ type: 'progress', current: parseInt(match[1]), total: parseInt(match[2]), label: match[3] || '' }) + "\n";
                    res.write(payloadOut);
                } else if (str.includes('[STATUS]')) {
                    res.write(JSON.stringify({ status: "streaming", message: str.replace('[STATUS]', '').trim() }) + "\n");
                }
            }
        });
        psParse.stderr.on('data', (data) => console.error(`[Parser Error]: ${data}`));

        psParse.on('close', (code) => {
            if (code !== 0) {
                console.log(`Parser failed with code ${code}`);
                return res.end(JSON.stringify({ error: "Parser failed" }));
            }

            console.log(`[+] Parser complete. Moving to Analyzer...`);
            res.write(JSON.stringify({ status: "streaming", message: "Parser complete. Initializing Heuristic Analyzer..." }) + "\n");
            // 2. Run Analyzer on the newly generated writable_paths.json
            const writableJson = path.join(projPath, 'writable_paths.json');

            const psAnalyze = spawn('powershell.exe', [
                '-ExecutionPolicy', 'Bypass',
                '-File', analyzeScript,
                '-JsonFeed', writableJson,
                '-Silent'
            ], { cwd: ROOT_DIR });

            psAnalyze.stdout.on('data', (data) => {
                const str = data.toString();
                // console.log(`[Analyzer]: ${str.trim()}`);
                if (str.includes('[STATUS]')) {
                    res.write(JSON.stringify({ status: "streaming", message: str.replace('[STATUS]', '').trim() }) + "\n");
                }
            });
            psAnalyze.stderr.on('data', (data) => console.error(`[Analyzer Error]: ${data}`));

            psAnalyze.on('close', (acode) => {
                if (acode !== 0) {
                    return res.end(JSON.stringify({ error: "Analyzer failed" }));
                }

                console.log(`[+] Analyzer complete. Fetching generated queues...`);
                res.write(JSON.stringify({ status: "streaming", message: "Fetching generated intelligence..." }) + "\n");
                // Send back final outputs!
                const highConf = readSafeJson(path.join(projPath, 'high_confidence_leads.json'));
                const cognitive = readSafeJson(path.join(projPath, 'cognitive_review_queue.json'));

                try { fs.unlinkSync(csvPath); } catch (ex) { } // Cleanup the massive CSV trace

                res.end(JSON.stringify({
                    success: true,
                    isRawJson: false,
                    highConfidence: highConf,
                    cognitiveQueue: cognitive
                }));
            });
        });

        return; // We stream responses back inside the callbacks
    }

    // Unsupported format
    fs.unlinkSync(req.file.path);
    res.status(400).json({ error: 'Unsupported file format. Please upload .json or .csv' });
});

app.post('/api/models', async (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(401).json({ error: "Missing API Key" });

    try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
        if (!response.ok) throw new Error("API Error: Valid Key Required");

        const data = await response.json();
        const validModels = (data.models || [])
            .filter(m => m.supportedGenerationMethods && m.supportedGenerationMethods.includes('generateContent'))
            .map(m => ({
                id: m.name.replace('models/', ''),
                name: m.displayName || m.name,
                version: m.version
            }));

        res.json({ success: true, models: validModels });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/analyze-stream', async (req, res) => {
    const { apiKey, modelId, queue } = req.body;
    if (!apiKey) return res.status(401).json({ error: "Missing API Key" });
    if (!queue || !Array.isArray(queue)) return res.status(400).json({ error: "Invalid queue array" });

    // Setup Server-Sent Events
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: modelId || "gemini-1.5-flash" });

        // Chunking the queue into larger groups of 150 to heavily preserve rate limits (15 RPM free tier)
        let tokensUsed = 0;
        const chunkSize = 150;

        for (let i = 0; i < queue.length; i += chunkSize) {
            const chunk = queue.slice(i, i + chunkSize);

            const prompt = `You are a skeptical, elite Security Researcher analyzing Sysinternals Procmon telemetry. 
You are hunting for Local Privilege Escalation (LPE), DLL Hijacking, COM Hijacking, and phantom DLL load vectors. The telemetry provided shows files that a low-privileged user can write to, which have been operated on by higher-privileged processes.

CRITICAL INSTRUCTIONS:
1. BE CREATIVE BUT SKEPTICAL: Think like a Red Teamer and a Security Researcher. Consider all execution vectors (DLL sideloading, unquoted service paths, arbitrary file writes, WMI, scheduled tasks, file redirection, coerced authentication, etc). However, do NOT simply assume every interaction is a vulnerability.
2. CALL OUT FALSE POSITIVES: Do not be afraid to be deeply skeptical. High-privileged processes (e.g. MsMpEng.exe, SearchIndexer.exe, svchost.exe) routinely map or read user files purely for scanning, indexing, or telemetry. Just because an EDR maps a DLL does NOT mean it executes it. If it looks like a benign operation or a typical AV scan, explicitly declare it a False Positive and explain why.
3. CRITICAL INTEGRITY RULE: Verify the 'Integrity' value mathematically strictly! If the Integrity is 'Low', 'Medium', 'Medium Plus', or 'AppContainer', it mathematically CANNOT be a Local Privilege Escalation (LPE) because the executing agent holds zero system elevation! It may be a valid unprivileged code execution/hijacking vulnerability, but you must explicitly state it is NOT an LPE. Only 'High' or 'System' Integrity processes result in Privilege Escalation.
4. PROVIDE A CONFIDENCE VERDICT: Prefix the beginning of your 'Hint' string with an explicit confidence verdict tag (e.g., "[VERDICT: HIGH CONFIDENCE LPE]", "[VERDICT: HIGH CONFIDENCE HIJACKING]", "[VERDICT: LIKELY FALSE POSITIVE]", or "[VERDICT: AMBIGUOUS - NEEDS REVERSING]").
5. DEEP CONTEXT: Use the 'Operation' and 'Detail' fields to prove your verdict (e.g., 'CreateFileMapping' with only READ access is likely a scan).

Input JSON:
${JSON.stringify(chunk)}

Return a raw JSON array of objects with the exact same fields as input, but replace the 'Hint' field with your advanced deductive analysis. Do NOT use markdown codeblock wrappers (\`\`\`json). Return STRICTLY JSON.`;

            let retries = 0;
            let success = false;

            while (!success && retries < 3) {
                try {
                    const result = await model.generateContent(prompt);
                    let responseText = result.response.text().trim();

                    let tokensForThisChunk = 0;
                    if (result.response.usageMetadata && result.response.usageMetadata.totalTokenCount) {
                        tokensForThisChunk = result.response.usageMetadata.totalTokenCount;
                    } else {
                        tokensForThisChunk = 150; // fallback arbitrary guess
                    }
                    tokensUsed += tokensForThisChunk;
                    let jsonStr = responseText;
                    
                    // Fallback to strip markdown if present
                    if (jsonStr.startsWith('```json')) {
                        jsonStr = jsonStr.replace(/^```json\n/, '').replace(/\n```$/, '');
                    }

                    // Systematically yank out the JSON array ignoring all conversational filler
                    const arrayMatch = jsonStr.match(/\[\s*\{[\s\S]*\}\s*\]/);
                    if (arrayMatch) {
                        jsonStr = arrayMatch[0];
                    }

                    const jsonArray = JSON.parse(jsonStr);

                    // Send the chunk update
                    res.write(`data: ${JSON.stringify({ type: 'chunk', items: jsonArray, currentTokensUsed: tokensUsed })}\n\n`);
                    success = true; // Loop break indicator
                } catch (err) {
                    // Check explicitly for Free Tier RPM 429
                    if ((err.status === 429 || err.message.includes('429')) && retries < 2) {
                        res.write(`data: ${JSON.stringify({ type: 'error', message: "[QUOTA REACHED] Going to sleep for 60 seconds natively to reset Free Tier limits..." })}\n\n`);
                        await new Promise(resolve => setTimeout(resolve, 61000));
                        retries++;
                    } else {
                        res.write(`data: ${JSON.stringify({ type: 'error', message: "Failed segment: " + err.message })}\n\n`);
                        break;
                    }
                }
            }
        }

        res.write(`data: ${JSON.stringify({ type: 'done', finalTokens: tokensUsed })}\n\n`);
        res.end();
    } catch (e) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: 'Fatal API Error: ' + e.message })}\n\n`);
        res.end();
    }
});

// --- MARKDOWN REPORT MANAGEMENT API ---

// API: Upload .md Report
app.post('/api/upload-report', upload.single('reportFile'), (req, res) => {
    let activeProject = req.body.project || 'Default_Project';
    const projReports = path.join(PROJECTS_DIR, activeProject, 'reports');
    if (!fs.existsSync(projReports)) fs.mkdirSync(projReports, { recursive: true });

    if (!req.file || path.extname(req.file.originalname).toLowerCase() !== '.md') {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Must be an .md file' });
    }

    const targetPath = path.join(projReports, req.file.originalname);
    fs.renameSync(req.file.path, targetPath);
    res.json({ success: true });
});

// API: Fetch and Parse Reports
app.post('/api/reports', (req, res) => {
    let activeProject = req.body.project || 'Default_Project';
    const projReports = path.join(PROJECTS_DIR, activeProject, 'reports');

    if (!fs.existsSync(projReports)) {
        return res.json({ success: true, reports: [] });
    }

    const reports = [];
    const files = fs.readdirSync(projReports).filter(f => f.endsWith('.md'));

    for (const f of files) {
        const content = fs.readFileSync(path.join(projReports, f), 'utf8');
        const lines = content.split('\n');
        const findings = [];
        let curFinding = null;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const matchUnchecked = line.match(/^\s*-\s*\[ \]\s*(.*)/);
            const matchChecked = line.match(/^\s*-\s*\[[xX]\]\s*(.*)/);

            if (matchUnchecked || matchChecked) {
                if (curFinding) findings.push(curFinding);
                curFinding = {
                    id: i, // index of line to easily rewrite it later
                    text: (matchUnchecked ? matchUnchecked[1] : matchChecked[1]).trim(),
                    checked: !!matchChecked,
                    details: []
                };
            } else if (curFinding && line.trim().startsWith('-')) {
                curFinding.details.push(line.trim());
            }
        }
        if (curFinding) findings.push(curFinding);

        reports.push({ file: f, findings });
    }

    res.json({ success: true, reports });
});

// API: Toggle findings inside the MD natively!
app.post('/api/toggle-report', (req, res) => {
    let { project, file, lineIndex, checkState } = req.body;
    if (!project) project = 'Default_Project';

    const filePath = path.join(PROJECTS_DIR, project, 'reports', file);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    if (lineIndex >= 0 && lineIndex < lines.length) {
        if (checkState) {
            lines[lineIndex] = lines[lineIndex].replace(/-\s*\[ \]/, '- [x]');
        } else {
            lines[lineIndex] = lines[lineIndex].replace(/-\s*\[[xX]\]/, '- [ ]');
        }
        fs.writeFileSync(filePath, lines.join('\n'));
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Invalid line index' });
    }
});

// API: Save raw memory states back to disk
app.post('/api/save-state', (req, res) => {
    let { project, highConfidence, cognitiveQueue } = req.body;
    if (!project) return res.status(400).json({ error: 'Missing project name' });

    const projPath = path.join(PROJECTS_DIR, project);
    if (!fs.existsSync(projPath)) fs.mkdirSync(projPath, { recursive: true });

    if (Array.isArray(highConfidence)) {
        // Strip out the internal UI metadata props before saving
        const cleanHc = highConfidence.map(({ OrigIdx, _isHighConf, ...rest }) => rest);
        fs.writeFileSync(path.join(projPath, 'high_confidence_leads.json'), JSON.stringify(cleanHc, null, 4));
    }

    if (Array.isArray(cognitiveQueue)) {
        const cleanCg = cognitiveQueue.map(({ OrigIdx, _isHighConf, ...rest }) => rest);
        fs.writeFileSync(path.join(projPath, 'cognitive_review_queue.json'), JSON.stringify(cleanCg, null, 4));
    }

    res.json({ success: true });
});

app.listen(port, () => {
    console.log(`[+] Web Dashboard running on http://localhost:${port}`);
    console.log(`[+] Awaiting connections...`);
});
