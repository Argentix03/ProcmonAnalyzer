# Procmon Analyzer

A high-performance pipeline and interactive web dashboard connecting Sysinternals Process Monitor (Procmon) traces directly to LLM Cognitive Agents.   

Procmon Analyzer enables triage execution risks from analysis of a procmon trace.

## Features 
*   **Dual-Orchestration Parsing** - First, traces are heuristically analyzed across a local offline PowerShell pipeline.
*   **Gemini Streaming Resolution** - Unresolved or complex logic traces are piped dynamically over Server-Sent Events (SSE) asynchronously using native Google Generative AI SDK APIs.
*   **Quota Optimization Engine** - Attempted to be efficient on request quotas. Promps the user for estimated amounts of tokens consumed when using cognitive AI analysis.
*   **Project Workspaces** - Support for isolating different analyses in the UI.
*   **Custom Prompting Models** - Supports user-selection of advanced Gemini LLMs dynamically fetched from API hooks directly in your UI settings.
*   **Agent Analysis without API** - Supports agents analysis without Gemini API with your favorite agents via skill.md stuff when invoked from a normal agent (at least it did so with AntiGravity).  

## UI Setup

1. Install dependencies natively using Node.js:
```bash
cd ui
npm install
```

2. Run the internal background Server:
```bash
node server.js
```

3. Navigate to \`http://localhost:3000\` and drop in your Procmon `.CSV` exports. *(Note: You must convert `.PML` binary traces using Sysinternals first)*.

4. Insert API Key and select your Agent / 

# Usage
1. Record a session with Procmon focusing mainly on file access operations.
2. Save as CSV.
3. Start AntiGravity and ask it to run a full analysis on your procmon trace / Open the UI and drop the file in for analysis. You can also drop analysis result files (.json) into the UI while using the analysis itself without UI.
