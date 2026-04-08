/*
 * Copyright 2026 The Sigstore Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import encoding from 'k6/encoding';

// ---------------------------------------------------------------------------
// Configuration via environment variables
// ---------------------------------------------------------------------------
const REKOR_URL      = __ENV.REKOR_URL      || 'http://localhost:3000';
const WRITE_QPS      = parseInt(__ENV.WRITE_QPS      || '50', 10);
const WRITER_PRE_VUS = parseInt(__ENV.WRITER_PRE_VUS || '50', 10);
const WRITER_MAX_VUS = parseInt(__ENV.WRITER_MAX_VUS || '200', 10);
const TAILER_VUS     = parseInt(__ENV.TAILER_VUS     || '10', 10);
const DURATION       = __ENV.DURATION       || '1m';
const TAILER_POLL_MS = parseInt(__ENV.TAILER_POLL_MS || '500', 10);

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const entryAddDuration  = new Trend('rekor_entry_add_duration', true);
const entryReadDuration = new Trend('rekor_entry_read_duration', true);

// ---------------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    writer: {
      executor: 'constant-arrival-rate',
      rate: WRITE_QPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: WRITER_PRE_VUS,
      maxVUs: WRITER_MAX_VUS,
      exec: 'writer',
    },
    tailer: {
      executor: 'constant-vus',
      vus: TAILER_VUS,
      duration: DURATION,
      exec: 'tailer',
      startTime: '3s',
    },
  },
  thresholds: {
    'http_req_duration{scenario:writer}': ['p(95)<5000'],
    'http_req_duration{scenario:tailer}': ['p(95)<1000'],
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function arrayBufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function arrayBufToBase64(buf) {
  return encoding.b64encode(new Uint8Array(buf), 'std');
}

function derToPem(derBuf, label) {
  const b64 = arrayBufToBase64(derBuf);
  let pem = `-----BEGIN ${label}-----\n`;
  for (let i = 0; i < b64.length; i += 64) {
    pem += b64.slice(i, i + 64) + '\n';
  }
  pem += `-----END ${label}-----\n`;
  return pem;
}

// Convert IEEE P1363 signature (r||s) to ASN.1 DER SEQUENCE(INTEGER(r), INTEGER(s)).
// P-256 produces 64-byte P1363 signatures (32 bytes each for r and s).
function p1363ToDer(p1363Buf) {
  const p1363 = new Uint8Array(p1363Buf);
  const half = p1363.length / 2;
  const r = p1363.slice(0, half);
  const s = p1363.slice(half);

  function integerBytes(val) {
    // Strip leading zeroes but keep at least one byte.
    let start = 0;
    while (start < val.length - 1 && val[start] === 0) {
      start++;
    }
    // If the high bit is set, prepend a 0x00 so it's interpreted as positive.
    const needsPad = val[start] >= 0x80;
    const len = val.length - start + (needsPad ? 1 : 0);
    const out = new Uint8Array(len);
    if (needsPad) {
      out[0] = 0x00;
      out.set(val.slice(start), 1);
    } else {
      out.set(val.slice(start));
    }
    return out;
  }

  const rEnc = integerBytes(r);
  const sEnc = integerBytes(s);

  // Each INTEGER: tag(0x02) + length + value
  const seqLen = 2 + rEnc.length + 2 + sEnc.length;

  // Build DER: SEQUENCE tag(0x30) + length + INTEGER(r) + INTEGER(s)
  const der = new Uint8Array(2 + seqLen);
  let offset = 0;
  der[offset++] = 0x30; // SEQUENCE tag
  der[offset++] = seqLen;
  der[offset++] = 0x02; // INTEGER tag
  der[offset++] = rEnc.length;
  der.set(rEnc, offset);
  offset += rEnc.length;
  der[offset++] = 0x02; // INTEGER tag
  der[offset++] = sEnc.length;
  der.set(sEnc, offset);

  return der;
}

function base64Encode(str) {
  return encoding.b64encode(str, 'std');
}

function stringToBytes(str) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// setup: generate an ECDSA P-256 key pair
// ---------------------------------------------------------------------------
export async function setup() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable
    ['sign', 'verify'],
  );

  // Export private key as PKCS8 DER → serialize as byte array for JSON transport
  const privDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const privBytes = Array.from(new Uint8Array(privDer));

  // Export public key as SPKI DER → PEM for the API
  const pubDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const pubPem = derToPem(pubDer, 'PUBLIC KEY');

  return { privBytes, pubPem };
}

// ---------------------------------------------------------------------------
// Writer scenario
// ---------------------------------------------------------------------------

// Module-level cache: each VU imports the private key once.
let _privKey = null;

async function getPrivateKey(privBytes) {
  if (_privKey) return _privKey;
  const buf = new Uint8Array(privBytes).buffer;
  _privKey = await crypto.subtle.importKey(
    'pkcs8',
    buf,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  return _privKey;
}

export async function writer(data) {
  const privKey = await getPrivateKey(data.privBytes);
  const pubPem = data.pubPem;

  // 1. Build a unique artifact
  const artifact = `rekor-k6-load:vu=${__VU}:iter=${__ITER}:ts=${Date.now()}`;
  const artifactBytes = stringToBytes(artifact);

  // 2. SHA-256 hash the artifact → hex
  const hashBuf = await crypto.subtle.digest('SHA-256', artifactBytes);
  const hashHex = arrayBufToHex(hashBuf);

  // 3. Sign the artifact bytes (ECDSA with SHA-256 — WebCrypto hashes internally)
  const sigP1363 = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privKey,
    artifactBytes,
  );

  // 4. Convert P1363 → DER, then base64
  const sigDer = p1363ToDer(sigP1363);
  const sigB64 = arrayBufToBase64(sigDer.buffer);

  // 5. Build the hashedrekord request body
  const body = JSON.stringify({
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      signature: {
        content: sigB64,
        publicKey: {
          content: base64Encode(pubPem),
        },
      },
      data: {
        hash: {
          algorithm: 'sha256',
          value: hashHex,
        },
      },
    },
  });

  // 6. POST the entry
  const res = http.post(`${REKOR_URL}/api/v1/log/entries`, body, {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'AddEntry' },
  });

  entryAddDuration.add(res.timings.duration);

  check(res, {
    'writer: status is 201': (r) => r.status === 201,
  });
}

// ---------------------------------------------------------------------------
// Tailer scenario
// ---------------------------------------------------------------------------

// Per-VU state for tailing
let _lastReadIndex = -1;
let _baselineSet = false;

export function tailer() {
  // 1. GET log info
  const logRes = http.get(`${REKOR_URL}/api/v1/log`, {
    tags: { name: 'GetLogInfo' },
  });

  const ok = check(logRes, {
    'tailer: log info 200': (r) => r.status === 200,
  });

  if (!ok) {
    sleep(TAILER_POLL_MS / 1000);
    return;
  }

  const logInfo = logRes.json();
  const treeSize = parseInt(logInfo.treeSize, 10);

  // 2. Set baseline on first call
  if (!_baselineSet) {
    _lastReadIndex = treeSize - 1;
    _baselineSet = true;
    sleep(TAILER_POLL_MS / 1000);
    return;
  }

  // 3. Read each new entry by index
  for (let i = _lastReadIndex + 1; i < treeSize; i++) {
    const entryRes = http.get(
      `${REKOR_URL}/api/v1/log/entries?logIndex=${i}`,
      { tags: { name: 'GetEntryByIndex' } },
    );

    entryReadDuration.add(entryRes.timings.duration);

    check(entryRes, {
      'tailer: entry read 200': (r) => r.status === 200,
    });

    _lastReadIndex = i;
  }

  // 4. Brief pause between polls
  sleep(TAILER_POLL_MS / 1000);
}
