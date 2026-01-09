const fs = require('fs');
try {
    const data = fs.readFileSync('ai_debug.log', 'utf8');
    console.log(data.slice(-2000));
} catch (e) {
    console.error(e);
}
