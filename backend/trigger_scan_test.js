
async function trigger() {
    try {
        // 1. Create Project
        const pRes = await fetch('http://localhost:3010/api/projects', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'Debug Scan', type: 'api', openapi_spec: '{"paths": {"/test": {"get": {"summary": "test"}}}}' })
        });
        const pData = await pRes.json();
        const pid = pData.id;
        console.log('Project created:', pid);

        // 2. Start Scan
        const sRes = await fetch(`http://localhost:3010/api/projects/${pid}/scan`, { method: 'POST' });
        const sData = await sRes.json();
        console.log('Scan started:', sData.scan_id);

    } catch (e) {
        console.error(e);
    }
}
trigger();
