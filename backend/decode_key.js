
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config({ path: '.env.local' });

const key = (process.env.LLM_API_KEY || '').trim();
console.log("Current Key:", key);

if (key.length > 10) {
    // Try skipping "ABSK" prefix if present
    let toDecode = key;
    if (key.startsWith('ABSK')) {
        toDecode = key.substring(4);
    }

    try {
        const decoded = Buffer.from(toDecode, 'base64').toString('utf-8');
        console.log("Decoded Base64:", decoded);

        // Check for colon format
        if (decoded.includes(':')) {
            const parts = decoded.split(':');
            console.log(`Split Parts: ${parts.length}`);
            parts.forEach((p, i) => console.log(`Part ${i}: ${p.substring(0, 4)}...`));

            if (parts.length === 2) {
                const p0 = parts[0];
                console.log("Part 0 Length:", p0.length);
                console.log("Part 0 contains 'AKIA'?", p0.includes('AKIA'));
                console.log("Part 0 contains 'us-east-1'?", p0.includes('us-east-1'));
                console.log("Part 0 ends with:", p0.substring(p0.length - 5));

                // Maybe it's Bedrock<SPACE>Region... ?
                console.log("Part 0 contains space?", p0.includes(' '));
            }
        } else {
            console.log("Decoded string has no colons:", decoded.substring(0, 10));
        }
    } catch (e) {
        console.error("Failed to decode:", e.message);
    }
}
