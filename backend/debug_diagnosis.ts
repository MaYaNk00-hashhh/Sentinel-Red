
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

console.log('Node Version:', process.version);
console.log('Global Fetch:', typeof fetch);
console.log('Supabase URL:', process.env.SUPABASE_URL);

async function testConnection() {
    try {
        console.log('Testing connectivity to Supabase URL...');
        const res = await fetch(process.env.SUPABASE_URL as string);
        console.log('Response Status:', res.status); // Should be 200 or 404, not throw
    } catch (e) {
        console.error('Connectivity Check Failed:', e);
    }
}

testConnection();
