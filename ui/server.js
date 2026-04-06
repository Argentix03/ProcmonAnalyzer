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

// Helper to reliably read JSON
const readSafeJson = (filePath) => {
    try {
        if (fs.existsSync(filePath)) {
            const raw = fs.readFileSync(filePath, 'utf8');
            // Remove potential BOM from UTF8 PowerShell exports
            return JSON.parse(raw.replace(/^\uFEFF/, ''));
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
    
    // If it's pure JSON, just return it (Drag and drop pure JSON ingestion)
    if (ext === '.json') {
        const data = readSafeJson(req.file.path);
        return res.json({ success: true, isRawJson: true, data });
    }

    // Identify output project
    let activeProject = req.body.project || 'Default_Project';
    const projPath = path.join(PROJECTS_DIR, activeProject);
    if (!fs.existsSync(projPath)) fs.mkdirSync(projPath, { recursive: true });

    // If it's a CSV, we run the massive pipeline!
    if (ext === '.csv') {
        const csvPath = req.file.path;
        console.log(`[+] Received CSV ProcMon payload routing to Project: ${activeProject}`);
        
        const parseScript = path.join(ROOT_DIR, 'skills', 'Parse-ProcmonWriteables', 'scripts', 'ParseProcmonTraceTestWritablePaths.ps1');
        const analyzeScript = path.join(ROOT_DIR, 'skills', 'Analyze-ExecutionLeads', 'scripts', 'AnalyzeExecutionLeads.ps1');

        res.write(JSON.stringify({ status: "streaming", message: "Starting powershell sequence..." }) + "\n");

        // 1. Run Parser
        const psParse = spawn('powershell.exe', [
            '-ExecutionPolicy', 'Bypass',
            '-File', parseScript,
            '-CsvPath', csvPath,
            '-OutputPath', projPath,
            '-Silent'
        ], { cwd: ROOT_DIR });

        psParse.stdout.on('data', (data) => {
            const str = data.toString();
            console.log(`[Parser]: ${str.trim()}`);
            
            const match = str.match(/\[PROGRESS\] (\d+) \/ (\d+)/);
            if (match) {
                res.write(JSON.stringify({ type: 'progress', current: parseInt(match[1]), total: parseInt(match[2]) }) + "\n");
            }
        });
        psParse.stderr.on('data', (data) => console.error(`[Parser Error]: ${data}`));

        psParse.on('close', (code) => {
            if (code !== 0) {
                console.log(`Parser failed with code ${code}`);
                return res.end(JSON.stringify({ error: "Parser failed" }));
            }

            console.log(`[+] Parser complete. Moving to Analyzer...`);
            // 2. Run Analyzer on the newly generated writable_paths.json
            const writableJson = path.join(projPath, 'writable_paths.json');
            
            const psAnalyze = spawn('powershell.exe', [
                '-ExecutionPolicy', 'Bypass',
                '-File', analyzeScript,
                '-JsonFeed', writableJson,
                '-Silent'
            ], { cwd: ROOT_DIR });

            psAnalyze.stdout.on('data', (data) => console.log(`[Analyzer]: ${data}`));
            psAnalyze.stderr.on('data', (data) => console.error(`[Analyzer Error]: ${data}`));

            psAnalyze.on('close', (acode) => {
                if (acode !== 0) {
                     return res.end(JSON.stringify({ error: "Analyzer failed" }));
                }

                console.log(`[+] Analyzer complete. Fetching generated queues...`);
                // Send back final outputs!
                const highConf = readSafeJson(path.join(projPath, 'high_confidence_leads.json'));
                const cognitive = readSafeJson(path.join(projPath, 'cognitive_review_queue.json'));
                
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
            
            const prompt = `You are a world-class cybersecurity expert agent.
I have a list of file paths that a user can write to. Analyze each path and related processes for Local Privilege Escalation or hijacking opportunities.
Input JSON:
${JSON.stringify(chunk)}

Return a raw JSON array of objects with the exact same fields as input, but replace the "Hint" field with your advanced deductive analysis. Do NOT use markdown codeblock wrappers (\`\`\`json). Return STRICTLY JSON.`;
            
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
                    if (responseText.startsWith('```json')) {
                        responseText = responseText.replace(/^```json\n/, '').replace(/\n```$/, '');
                    }

                    const jsonArray = JSON.parse(responseText);

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

app.listen(port, () => {
    console.log(`[+] Web Dashboard running on http://localhost:${port}`);
    console.log(`[+] Awaiting connections...`);
});
