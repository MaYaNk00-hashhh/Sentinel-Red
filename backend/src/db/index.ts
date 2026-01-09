import low = require('lowdb');
import FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync('db.json');
const db: any = low(adapter);

// Set defaults if JSON file is empty
db.defaults({
    users: [],
    projects: [],
    scans: [],
    scanLogs: {}
}).write();

export default db;
