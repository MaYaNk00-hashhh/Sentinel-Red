
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config({ path: '.env.local' });

const key = (process.env.LLM_API_KEY || '').trim();
console.log("--- KEY ANALYSIS ---");
console.log("Raw Key Length:", key.length);

if (key.startsWith('ABSK')) {
    console.log("Detected ABSK Prefix.");
    const payload = key.substring(4);
    try {
        const decoded = Buffer.from(payload, 'base64').toString('utf-8');
        console.log("Decoded Length:", decoded.length);
        console.log("Decoded Start:", decoded.substring(0, 20));

        if (decoded.includes(':')) {
            const parts = decoded.split(':');
            console.log(`Split by ':' -> ${parts.length} parts.`);
            parts.forEach((p, i) => {
                console.log(`Part ${i} [Len: ${p.length}]: ${p.substring(0, 5)}...${p.substring(p.length - 5)}`);
                if (p.includes('AKIA')) console.log(`  -> Part ${i} HAS 'AKIA'`);
                if (p.includes('ASIA')) console.log(`  -> Part ${i} HAS 'ASIA'`);
            });

            if (parts.length >= 2) {
                const p1 = parts[1];
                console.log("Part 1 Raw:", p1);
                try {
                    const p1Decoded = Buffer.from(p1, 'base64').toString('utf-8');
                    console.log("Part 1 Decoded:", p1Decoded);
                    if (p1Decoded.includes('AKIA') || p1Decoded.includes('ASIA')) {
                        console.log("SUCCESS! Found AWS Key in Part 1!");
                    }
                } catch (e) {
                    console.log("Part 1 is not Base64 or failed to decode.");
                }
            }
        } else {
            console.log("NO COLONS FOUND in decoded string.");
        }
    } catch (e) {
        console.error("Base64 Decode Failed:", e.message);
    }
} else {
    console.log("No ABSK Prefix.");
}
