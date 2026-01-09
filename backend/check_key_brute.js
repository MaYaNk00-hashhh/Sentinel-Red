
const { BedrockRuntimeClient, InvokeModelCommand } = require("@aws-sdk/client-bedrock-runtime");
const dotenv = require('dotenv');
dotenv.config({ path: '.env.local' });

const key = (process.env.LLM_API_KEY || '').trim();

if (!key.startsWith('ABSK')) {
    console.log("Key does not start with ABSK. Aborting.");
    process.exit(1);
}

const raw = key.substring(4);
const decoded = Buffer.from(raw, 'base64').toString('utf-8').trim();
const parts = decoded.split(':');

console.log("Decoded Parts:", parts.length);
if (parts.length < 2) {
    console.log("Not enough parts.");
    process.exit(1);
}

const p0 = parts[0]; // "Bedrock-at-..."
const p1 = parts[1]; // "JLty..." (60 chars)

const strategies = [
    { name: "Split 20/40", ak: p1.substring(0, 20), sk: p1.substring(20) },
    { name: "Split 40/20", ak: p1.substring(0, 40), sk: p1.substring(40) },
    { name: "Metadata as ID", ak: p0, sk: p1 },
    { name: "Metadata as Secret", ak: p1, sk: p0 },
];

async function testCreds(strategy) {
    console.log(`\n--- Testing: ${strategy.name} ---`);
    console.log(`AK: ${strategy.ak.substring(0, 5)}...`);
    console.log(`SK: ${strategy.sk.substring(0, 5)}...`);

    const client = new BedrockRuntimeClient({
        region: "us-east-1",
        credentials: {
            accessKeyId: strategy.ak,
            secretAccessKey: strategy.sk
        }
    });

    const prompt = "\n\nHuman: Hi\n\nAssistant:";
    const payload = {
        prompt,
        max_tokens_to_sample: 10,
    };

    try {
        const command = new InvokeModelCommand({
            modelId: "anthropic.claude-v2",
            contentType: "application/json",
            accept: "application/json",
            body: JSON.stringify(payload),
        });
        await client.send(command);
        console.log("✅ SUCCESS! Valid Credentials Found!");
        return true;
    } catch (e) {
        if (e.name === 'UnrecognizedClientException') {
            console.log("❌ Failed: Unrecognized Access Key (Invalid user/ID)");
        } else if (e.name === 'InvalidSignatureException') {
            console.log("❌ Failed: Invalid Signature (Wrong Secret)");
        } else {
            console.log(`❌ Failed: ${e.name} - ${e.message}`);
        }
        return false;
    }
}

async function run() {
    for (const strat of strategies) {
        if (await testCreds(strat)) break;
    }
}

run();
