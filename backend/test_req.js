
async function test() {
    try {
        const res = await fetch('http://localhost:3010/api/projects', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'Test Proj JS', type: 'api' })
        });
        const text = await res.text();
        console.log('Status:', res.status);
        console.log('Body:', text);
    } catch (e) {
        console.error(e);
    }
}
test();
