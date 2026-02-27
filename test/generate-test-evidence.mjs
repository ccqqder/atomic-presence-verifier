#!/usr/bin/env node
// Generate test evidence files for E2E testing of the verifier
// Uses the same Ed25519 + SHA-256 algorithms as the AtomicPresence iOS app

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Import noble-ed25519 from vendor
const ed = await import('../js/vendor/noble-ed25519.js');

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

// Generate Ed25519 key pair
const privateKey = ed.utils.randomPrivateKey();
const publicKey = await ed.getPublicKeyAsync(privateKey);
const publicKeyHex = bytesToHex(publicKey);

// Random salt (16 bytes)
const salt = new Uint8Array(16);
crypto.getRandomValues(salt);
const saltHex = bytesToHex(salt);

// Timestamps
const now = Date.now();
const startTimestamp = now - 30000; // 30 seconds ago
const endTimestamp = now;

// Device ID (fake but valid format)
const deviceIdHash = await sha256(new TextEncoder().encode('test-device-id'));
const deviceId = bytesToHex(deviceIdHash).substring(0, 16);

const appVersion = '1.0.1';

// Generate initial hash
const genesisString = `AtomicPresence_Recording_${startTimestamp}`;
const initialHash = await sha256(new TextEncoder().encode(genesisString));
const initialHashHex = bytesToHex(initialHash);

// Simulate a short hash chain (30 frames at 1fps)
const frameCount = 30;
let prevHash = initialHash;
for (let i = 0; i < frameCount; i++) {
    const ts = startTimestamp + (i + 1) * 1000;
    const tsBuf = new ArrayBuffer(8);
    const view = new DataView(tsBuf);
    view.setBigInt64(0, BigInt(ts));
    const input = new Uint8Array(32 + 8 + 16);
    input.set(prevHash, 0);
    input.set(new Uint8Array(tsBuf), 32);
    input.set(salt, 40);
    prevHash = await sha256(input);
}
const finalHashHex = bytesToHex(prevHash);

// ── Level 1 Session ──
const sessionId = 'TEST-' + crypto.randomUUID();
const l1Payload = [
    sessionId,
    String(startTimestamp),
    String(endTimestamp),
    initialHashHex,
    finalHashHex,
    String(frameCount),
    saltHex,
    deviceId,
    appVersion,
    publicKeyHex
].join('|');

const l1Signature = await ed.signAsync(new TextEncoder().encode(l1Payload), privateKey);
const l1SignatureHex = bytesToHex(l1Signature);

const l1Session = {
    sessionId,
    startTimestamp,
    endTimestamp,
    initialHashChainValue: initialHashHex,
    finalHashChainValue: finalHashHex,
    frameCount,
    salt: saltHex,
    deviceId,
    appVersion,
    signature: l1SignatureHex,
    publicKey: publicKeyHex
};

// ── Level 2 Evidence (with fake audio file) ──
// Create a small fake m4a file
const fakeAudio = new Uint8Array(1024);
crypto.getRandomValues(fakeAudio);
const fileChecksum = bytesToHex(await sha256(fakeAudio));

const l2Payload = [
    fileChecksum,
    String(startTimestamp),
    String(endTimestamp),
    initialHashHex,
    finalHashHex,
    String(frameCount),
    saltHex,
    deviceId,
    appVersion,
    publicKeyHex
].join('|');

const l2Signature = await ed.signAsync(new TextEncoder().encode(l2Payload), privateKey);
const l2SignatureHex = bytesToHex(l2Signature);

const l2Evidence = {
    fileChecksum,
    startTimestamp,
    endTimestamp,
    initialHashChainValue: initialHashHex,
    finalHashChainValue: finalHashHex,
    frameCount,
    salt: saltHex,
    deviceId,
    appVersion,
    signature: l2SignatureHex,
    publicKey: publicKeyHex
};

// ── Write files ──
const outDir = join(__dirname, 'fixtures');
mkdirSync(outDir, { recursive: true });

writeFileSync(join(outDir, 'Level1_test.session.json'), JSON.stringify(l1Session, null, 2));
writeFileSync(join(outDir, 'AP_test.evidence.json'), JSON.stringify(l2Evidence, null, 2));
writeFileSync(join(outDir, 'AP_test.m4a'), fakeAudio);

// Also create a tampered version (changed timestamp)
const l1Tampered = { ...l1Session, startTimestamp: startTimestamp + 1 };
writeFileSync(join(outDir, 'Level1_tampered.session.json'), JSON.stringify(l1Tampered, null, 2));

console.log('Test fixtures generated in', outDir);
console.log('  Level1_test.session.json  — valid L1 session');
console.log('  AP_test.evidence.json     — valid L2 evidence');
console.log('  AP_test.m4a               — matching fake audio (1KB)');
console.log('  Level1_tampered.session.json — tampered (should FAIL)');
