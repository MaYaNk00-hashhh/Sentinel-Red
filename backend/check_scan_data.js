
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');
dotenv.config({ path: '.env.local' });

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error("Missing Supabase credentials.");
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

async function checkLatestScan() {
    console.log("Fetching latest scan...");
    const { data, error } = await supabase
        .from('scans')
        .select('id, project_id, status, attack_graph')
        .order('started_at', { ascending: false })
        .limit(1)
        .single();

    if (error) {
        console.error("Error fetching scan:", error);
        return;
    }
    console.log(data.id);
}

checkLatestScan();
