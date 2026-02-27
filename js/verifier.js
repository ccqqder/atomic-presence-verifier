// AtomicPresence Open Verifier
// Ed25519 signature + SHA-256 checksum verification
// Security: ZERO innerHTML usage — all DOM via createElement/textContent

import * as ed from './vendor/noble-ed25519.js';

// ─── State ───────────────────────────────────────────────────────────────────
let mediaFile = null;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// ─── Safe DOM Helpers ────────────────────────────────────────────────────────

function setResult(id, status, title, detailParts) {
    const el = document.getElementById(id);
    el.className = 'result-card ' + status;
    el.replaceChildren();

    const icons = { pass: '\u2713', fail: '\u2717', running: '\u27F3', skip: '\u2014' };

    const header = document.createElement('div');
    header.className = 'result-header';

    const icon = document.createElement('span');
    icon.className = 'result-icon';
    icon.textContent = icons[status] || '';
    header.appendChild(icon);

    const titleEl = document.createElement('span');
    titleEl.className = 'result-title';
    titleEl.textContent = title;
    header.appendChild(titleEl);

    el.appendChild(header);

    if (detailParts && detailParts.length > 0) {
        const detail = document.createElement('div');
        detail.className = 'result-detail';
        for (const part of detailParts) {
            const line = document.createElement('div');
            if (part.label) {
                const lbl = document.createElement('span');
                lbl.className = 'label';
                lbl.textContent = part.label + ': ';
                line.appendChild(lbl);
            }
            const val = document.createTextNode(part.value);
            line.appendChild(val);
            detail.appendChild(line);
        }
        el.appendChild(detail);
    }
}

function setProgress(id, title, current, total) {
    const el = document.getElementById(id);
    el.className = 'result-card running';
    el.replaceChildren();

    const header = document.createElement('div');
    header.className = 'result-header';
    const icon = document.createElement('span');
    icon.className = 'result-icon';
    icon.textContent = '\u27F3';
    header.appendChild(icon);
    const titleEl = document.createElement('span');
    titleEl.className = 'result-title';
    titleEl.textContent = title;
    header.appendChild(titleEl);
    el.appendChild(header);

    const pct = Math.round((current / total) * 100);
    const detail = document.createElement('div');
    detail.className = 'result-detail';
    detail.textContent = current + '/' + total + ' (' + pct + '%)';
    el.appendChild(detail);

    const bar = document.createElement('div');
    bar.className = 'progress-bar';
    const fill = document.createElement('div');
    fill.className = 'progress-fill';
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    el.appendChild(bar);
}

function showSection(id) {
    document.getElementById(id).classList.remove('hidden');
}

function hideSection(id) {
    document.getElementById(id).classList.add('hidden');
}

// ─── File Info Display ───────────────────────────────────────────────────────

function showFileInfo(jsonFile, media, level) {
    const el = document.getElementById('fileInfo');
    el.replaceChildren();
    el.classList.remove('hidden');

    const levelLabels = {
        L1: 'Level 1 \u2014 Session Proof',
        L2: 'Level 2 \u2014 Audio Evidence',
        L3: 'Level 3 \u2014 Video Evidence'
    };

    const badge = document.createElement('div');
    badge.className = 'level-badge level-' + level.toLowerCase();
    badge.textContent = levelLabels[level] || level;
    el.appendChild(badge);

    const list = document.createElement('div');
    list.className = 'file-list';

    const jsonLine = document.createElement('div');
    jsonLine.className = 'file-entry';
    const jsonName = document.createElement('span');
    jsonName.className = 'file-name';
    jsonName.textContent = jsonFile.name;
    const jsonSize = document.createElement('span');
    jsonSize.className = 'file-size';
    jsonSize.textContent = formatBytes(jsonFile.size);
    jsonLine.appendChild(jsonName);
    jsonLine.appendChild(jsonSize);
    list.appendChild(jsonLine);

    if (media) {
        const mediaLine = document.createElement('div');
        mediaLine.className = 'file-entry';
        const mediaName = document.createElement('span');
        mediaName.className = 'file-name';
        mediaName.textContent = media.name;
        const mediaSize = document.createElement('span');
        mediaSize.className = 'file-size';
        mediaSize.textContent = formatBytes(media.size);
        mediaLine.appendChild(mediaName);
        mediaLine.appendChild(mediaSize);
        list.appendChild(mediaLine);
    }

    el.appendChild(list);
}

// ─── Evidence Details Display ────────────────────────────────────────────────

function showDetails(json) {
    const section = document.getElementById('details');
    section.classList.remove('hidden');

    const pre = document.getElementById('evidenceDetails');
    // Safe: textContent only, no innerHTML
    const display = {};
    const keysToShow = [
        'sessionId', 'fileChecksum',
        'startTimestamp', 'endTimestamp',
        'frameCount', 'deviceId', 'appVersion',
        'initialHashChainValue', 'finalHashChainValue',
        'salt', 'publicKey'
    ];
    for (const key of keysToShow) {
        if (json[key] !== undefined) {
            display[key] = json[key];
        }
    }
    pre.textContent = JSON.stringify(display, null, 2);
}

// ─── Reset ───────────────────────────────────────────────────────────────────

function addResetButton() {
    const container = document.querySelector('.container');
    // Remove existing reset button if any
    const existing = document.getElementById('resetBtn');
    if (existing) existing.remove();

    const btn = document.createElement('button');
    btn.id = 'resetBtn';
    btn.className = 'reset-btn';
    btn.textContent = 'VERIFY ANOTHER FILE';
    btn.addEventListener('click', resetUI);
    container.appendChild(btn);
}

function resetUI() {
    mediaFile = null;

    // Hide sections
    hideSection('fileInfo');
    hideSection('results');
    hideSection('details');

    // Clear result cards
    for (const id of ['signatureResult', 'checksumResult', 'qrChainResult']) {
        const el = document.getElementById(id);
        el.className = 'result-card';
        el.replaceChildren();
    }

    // Clear file info
    document.getElementById('fileInfo').replaceChildren();
    document.getElementById('evidenceDetails').textContent = '';

    // Remove reset button
    const btn = document.getElementById('resetBtn');
    if (btn) btn.remove();

    // Reset drop zone
    const dropZone = document.getElementById('dropZone');
    dropZone.classList.remove('hidden');

    // Reset file input
    document.getElementById('fileInput').value = '';
}

// ─── Level Detection ─────────────────────────────────────────────────────────

function detectLevel(json, media) {
    if (json.sessionId && !json.fileChecksum) {
        return 'L1';
    }
    if (json.fileChecksum) {
        if (media) {
            const ext = media.name.split('.').pop().toLowerCase();
            if (ext === 'mp4' || ext === 'mov') {
                return 'L3';
            }
        }
        return 'L2';
    }
    // Fallback: treat as L1 if sessionId exists
    if (json.sessionId) return 'L1';
    return null;
}

// ─── Signature Verification ──────────────────────────────────────────────────

function buildSignaturePayload(json, level) {
    const anchor = level === 'L1' ? String(json.sessionId) : String(json.fileChecksum);
    const parts = [
        anchor,
        String(json.startTimestamp),
        String(json.endTimestamp),
        String(json.initialHashChainValue),
        String(json.finalHashChainValue),
        String(json.frameCount),
        String(json.salt),
        String(json.deviceId),
        String(json.appVersion),
        String(json.publicKey)
    ];
    return parts.join('|');
}

async function verifySignature(json, level) {
    try {
        const payloadStr = buildSignaturePayload(json, level);
        const messageBytes = new TextEncoder().encode(payloadStr);

        const signatureHex = json.signature;
        const publicKeyHex = json.publicKey;

        if (!signatureHex || !publicKeyHex) {
            return { valid: false, error: 'Missing signature or publicKey in JSON.' };
        }

        if (signatureHex.length !== 128) {
            return { valid: false, error: 'Invalid signature length (expected 128 hex chars, got ' + signatureHex.length + ').' };
        }

        if (publicKeyHex.length !== 64) {
            return { valid: false, error: 'Invalid publicKey length (expected 64 hex chars, got ' + publicKeyHex.length + ').' };
        }

        const signature = hexToBytes(signatureHex);
        const publicKey = hexToBytes(publicKeyHex);

        const valid = await ed.verifyAsync(signature, messageBytes, publicKey);
        return { valid: valid, error: null };
    } catch (err) {
        return { valid: false, error: 'Signature verification error: ' + err.message };
    }
}

// ─── SHA-256 Checksum ────────────────────────────────────────────────────────

async function computeFileChecksum(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return bytesToHex(new Uint8Array(hashBuffer));
}

// ─── Verification Pipeline ───────────────────────────────────────────────────

async function runVerification(json, level) {
    showSection('results');

    // Step 1: Signature verification (all levels)
    setResult('signatureResult', 'running', 'VERIFYING SIGNATURE...', []);
    setResult('checksumResult', 'skip', 'CHECKSUM', [{ value: 'Waiting...' }]);
    setResult('qrChainResult', 'skip', 'QR CHAIN', [{ value: 'Waiting...' }]);

    const sigResult = await verifySignature(json, level);

    if (sigResult.valid) {
        setResult('signatureResult', 'pass', 'SIGNATURE VALID', [
            { label: 'Algorithm', value: 'Ed25519' },
            { label: 'Public Key', value: json.publicKey.substring(0, 16) + '...' + json.publicKey.substring(48) }
        ]);
    } else {
        const details = [{ label: 'Algorithm', value: 'Ed25519' }];
        if (sigResult.error) {
            details.push({ label: 'Error', value: sigResult.error });
        }
        setResult('signatureResult', 'fail', 'SIGNATURE INVALID', details);
    }

    // Step 2: Checksum verification (L2/L3 only)
    if (level !== 'L1') {
        if (!mediaFile) {
            setResult('checksumResult', 'fail', 'CHECKSUM FAILED', [
                { value: 'No media file provided. Drop the corresponding audio/video file to verify checksum.' }
            ]);
        } else {
            setResult('checksumResult', 'running', 'COMPUTING CHECKSUM...', [
                { label: 'File', value: mediaFile.name },
                { label: 'Size', value: formatBytes(mediaFile.size) }
            ]);

            try {
                const computed = await computeFileChecksum(mediaFile);
                const expected = json.fileChecksum.toLowerCase();
                const match = computed === expected;

                if (match) {
                    setResult('checksumResult', 'pass', 'CHECKSUM MATCH', [
                        { label: 'Algorithm', value: 'SHA-256' },
                        { label: 'Hash', value: computed.substring(0, 16) + '...' + computed.substring(48) }
                    ]);
                } else {
                    setResult('checksumResult', 'fail', 'CHECKSUM MISMATCH', [
                        { label: 'Algorithm', value: 'SHA-256' },
                        { label: 'Expected', value: expected.substring(0, 16) + '...' },
                        { label: 'Computed', value: computed.substring(0, 16) + '...' }
                    ]);
                }
            } catch (err) {
                setResult('checksumResult', 'fail', 'CHECKSUM ERROR', [
                    { label: 'Error', value: err.message }
                ]);
            }
        }
    } else {
        setResult('checksumResult', 'skip', 'CHECKSUM', [
            { value: 'Not applicable for Level 1 sessions.' }
        ]);
    }

    // Step 3: QR Chain (L3 only — placeholder for next task)
    if (level === 'L3' && mediaFile) {
        setResult('qrChainResult', 'skip', 'QR CHAIN', [
            { value: 'QR chain verification available in next update.' }
        ]);
    } else {
        setResult('qrChainResult', 'skip', 'QR CHAIN', [
            { value: 'Not applicable for this level.' }
        ]);
    }

    // Show evidence details
    showDetails(json);

    // Add reset button
    addResetButton();
}

// ─── File Processing ─────────────────────────────────────────────────────────

async function handleFiles(fileList) {
    if (!fileList || fileList.length === 0) return;

    let jsonFile = null;
    mediaFile = null;

    for (const file of fileList) {
        if (file.name.toLowerCase().endsWith('.json')) {
            jsonFile = file;
        } else {
            mediaFile = file;
        }
    }

    if (!jsonFile) {
        showSection('results');
        setResult('signatureResult', 'fail', 'NO JSON FILE', [
            { value: 'Please drop an .evidence.json or .session.json file.' }
        ]);
        setResult('checksumResult', 'skip', 'CHECKSUM', [{ value: 'Waiting for valid input.' }]);
        setResult('qrChainResult', 'skip', 'QR CHAIN', [{ value: 'Waiting for valid input.' }]);
        return;
    }

    // Parse JSON
    let json;
    try {
        const text = await jsonFile.text();
        json = JSON.parse(text);
    } catch (err) {
        showSection('results');
        setResult('signatureResult', 'fail', 'INVALID JSON', [
            { label: 'File', value: jsonFile.name },
            { label: 'Error', value: err.message }
        ]);
        setResult('checksumResult', 'skip', 'CHECKSUM', [{ value: 'Waiting for valid input.' }]);
        setResult('qrChainResult', 'skip', 'QR CHAIN', [{ value: 'Waiting for valid input.' }]);
        return;
    }

    // Detect level
    const level = detectLevel(json, mediaFile);
    if (!level) {
        showSection('results');
        setResult('signatureResult', 'fail', 'UNKNOWN FORMAT', [
            { value: 'JSON must contain either sessionId (L1) or fileChecksum (L2/L3).' }
        ]);
        setResult('checksumResult', 'skip', 'CHECKSUM', [{ value: 'Waiting for valid input.' }]);
        setResult('qrChainResult', 'skip', 'QR CHAIN', [{ value: 'Waiting for valid input.' }]);
        return;
    }

    // Hide drop zone, show file info
    hideSection('dropZone');
    showFileInfo(jsonFile, mediaFile, level);

    // Run verification
    await runVerification(json, level);
}

// ─── Event Binding ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    // Drag-and-drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
        handleFiles(e.dataTransfer.files);
    });

    // Click drop zone to trigger file input
    dropZone.addEventListener('click', (e) => {
        // Don't trigger if clicking the file input label/button itself
        if (e.target === fileInput || e.target.closest('.file-select-btn')) return;
        fileInput.click();
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
});
