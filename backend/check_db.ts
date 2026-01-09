
import { supabase } from '../src/db/supabase';

async function check() {
    console.log('Checking Supabase Connection...');
    const { data, error } = await supabase.from('projects').select('*').limit(1);
    if (error) {
        console.error('FAILED:', error.message);
    } else {
        console.log('SUCCESS: Projects table exists. Row count:', data.length);
    }
}

check();
