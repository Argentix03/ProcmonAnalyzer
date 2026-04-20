const fs = require('fs');
const path = require('path');

async function testUpload() {
    const filePath = path.resolve(__dirname, 'ShortDLLTrace.CSV');
    if (!fs.existsSync(filePath)) {
        console.error("Please place ShortDLLTrace.CSV in the root directory for this test!");
        return;
    }

    const { FormData } = await import('formdata-node');
    const { fileFromPath } = await import('formdata-node/file-from-path');
    
    const form = new FormData();
    form.set('project', 'Automated_Test_Project');
    form.set('reportFile', await fileFromPath(filePath));

    console.log("[*] Uploading CSV to Pipeline...");
    
    // Instead of raw fetch which buffers the full stream, we will use native http requests or read the body as chunked to simulate app.js
    const response = await fetch('http://localhost:3000/api/upload', {
        method: 'POST',
        body: form
    });
    
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        // Print exactly what the server outputs cleanly to verify streaming works
        process.stdout.write(decoder.decode(value, { stream: true }));
    }
    
    console.log("\n[+] Test complete!");
}

testUpload();
