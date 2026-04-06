# Procmon Analyzer 🛡️

A high-performance pipeline and interactive web dashboard connecting Sysinternals Process Monitor (Procmon) traces directly to LLM Cognitive Agents (Gemini 1.5/2.5/Pro). 

Procmon Analyzer enables threat hunters, incident responders, and security researchers to triage execution leaks, binary planting primitives, and LOLBin interactions asynchronously via intelligent automated streaming architectures and heuristics.

## Features 🚀
*   **Dual-Orchestration Parsing** - First, traces are heuristically analyzed across a local offline PowerShell pipeline.
*   **Gemini Streaming Resolution** - Unresolved or complex logic traces are piped dynamically over Server-Sent Events (SSE) asynchronously using native Google Generative AI SDK APIs.
*   **Quota Optimization Engine** - Intelligent native data array mapping (`OrigIdx`) prevents context limit violations by enforcing large-block queue logic while safely dodging standard `HTTP 429` Rate Limits dynamically by managing API rest-loops.
*   **Project Workspaces** - Full support for isolating different CSV/JSON trace analyses via dynamic UI contexts.
*   **Custom Prompting Models** - Live architecture mapping supports user-selection of advanced Gemini LLMs dynamically fetched from API hooks directly in your UI settings.

## Setup
You must acquire your own Google AI SDK API key (`AIza...`) to analyze traces cognitively. Standard free tier provides significant token limits capable of burning through average execution lead workloads instantly.

1. Install dependencies natively using Node.js:
\`\`\`bash
cd ui
npm install
\`\`\`

2. Run the internal background Server:
\`\`\`bash
node server.js
\`\`\`

3. Navigate to \`http://localhost:3000\` and drop in your Procmon `.CSV` exports. *(Note: You must convert `.PML` binary traces using Sysinternals first)*.

---
*Built via Agentic AI during live pair programming.*
