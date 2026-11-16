/**
 * FiveM Decrypt Backend
 * Node.js server — jalankan di VPS / lokal
 *
 * Install: npm install express multer jszip
 * Run:     node server.js
 * Port:    3000  (ubah PORT di bawah)
 */

const express  = require('express');
const multer   = require('multer');
const JSZip    = require('jszip');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');

const PORT = process.env.PORT || 3000;
const app    = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── CORS (biar bisa diakses dari web tool) ───────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Requested-With');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ─── Serve halaman status ──────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send(`
    <html><body style="font-family:monospace;background:#0C0D12;color:#E2E6F3;padding:40px">
    <h2>🔓 FiveM Decrypt Backend</h2>
    <p>Status: <span style="color:#22D3A5">Running on port ${PORT}</span></p>
    <p>Endpoint: <code>POST /decrypt</code></p>
    <p>Fields: <code>zip</code> (file), <code>grant</code> (file, opsional), <code>key</code> (string, opsional)</p>
    <p>Response: ZIP file ter-decrypt</p>
    </body></html>
  `);
});

// ─── Helpers ───────────────────────────────────────────────────────────────────
const RSC7 = 0x37435352;
const RSC8 = 0x38435352;

function isRSC(buf) {
  if (buf.length < 4) return false;
  const magic = buf.readUInt32LE(0);
  return magic === RSC7 || magic === RSC8;
}

function isText(buf) {
  const sample = buf.slice(0, Math.min(64, buf.length));
  const printable = [...sample].filter(b => b >= 32 && b < 127 || b === 10 || b === 13 || b === 9).length;
  return printable / sample.length > 0.75;
}

function isValid(dec) {
  if (!dec || dec.length < 4) return false;
  const magic = dec.readUInt32LE(0);
  return magic === RSC7 || magic === RSC8 || isText(dec);
}

function hexToBytes(hex) {
  const b = Buffer.alloc(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

function keyToBuffer(keyStr) {
  const raw = keyStr.replace(/^cfxk_/i, '').trim();
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) return hexToBytes(raw);
  try { return Buffer.from(raw, 'base64'); } catch {}
  return Buffer.from(raw, 'utf8');
}

function parseJWT(token) {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    const pad = s => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=');
    return JSON.parse(Buffer.from(pad(parts[1]), 'base64').toString('utf8'));
  } catch { return null; }
}

function parseGrants(text) {
  const map = {};
  const raw = text.trim();

  // JWT
  if (raw.startsWith('eyJ')) {
    const payload = parseJWT(raw);
    if (payload?.grants_clk) {
      return { __jwt: true, clk: payload.grants_clk };
    }
  }

  // XML
  for (const m of raw.matchAll(/name\s*=\s*["']([^"']+)["'][^>]*key\s*=\s*["']([^"']+)["']/gi))
    map[m[1].toLowerCase()] = m[2];
  for (const m of raw.matchAll(/key\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']([^"']+)["']/gi))
    map[m[2].toLowerCase()] = m[1];

  // JSON
  try {
    const j = JSON.parse(raw);
    const arr = Array.isArray(j) ? j : j.grants || j.resources || [];
    for (const e of arr) if (e.name && e.key) map[e.name.toLowerCase()] = e.key;
  } catch {}

  return { __jwt: false, clk: null, map };
}

// ─── Decrypt satu file ────────────────────────────────────────────────────────
function tryAll(buf, keyBuf) {
  if (buf.length < 16) return null;

  // Build key variants (48-byte keymaster key)
  const variants = [];
  if (keyBuf.length >= 48) {
    variants.push({ k: keyBuf.slice(0, 32),  iv: keyBuf.slice(32, 48), label: 'k[0:32]+iv[32:48]' });
    variants.push({ k: keyBuf.slice(16, 48), iv: keyBuf.slice(0, 16),  label: 'iv[0:16]+k[16:48]' });
  }
  if (keyBuf.length >= 32) {
    const k32 = keyBuf.slice(0, 32);
    const ivFile = buf.slice(0, 16);
    const ivZero = Buffer.alloc(16);
    variants.push({ k: k32, iv: ivFile, label: 'k[0:32]+iv_file' });
    variants.push({ k: k32, iv: ivZero, label: 'k[0:32]+iv_zero' });
    // SHA-256 derived key
    const kHash = crypto.createHash('sha256').update(keyBuf).digest();
    variants.push({ k: kHash, iv: ivFile, label: 'sha256(k)+iv_file' });
    variants.push({ k: kHash, iv: ivZero, label: 'sha256(k)+iv_zero' });
    if (keyBuf.length > 32) {
      const kL = keyBuf.slice(keyBuf.length - 32);
      variants.push({ k: kL, iv: ivFile, label: 'k[-32:]+iv_file' });
    }
  }

  for (const { k, iv, label } of variants) {
    // ── AES-256-CBC ──
    for (const data of [buf.slice(16), buf]) {
      try {
        const dec = crypto.createDecipheriv('aes-256-cbc', k, iv);
        dec.setAutoPadding(false);
        const out = Buffer.concat([dec.update(data), dec.final()]);
        if (isValid(out)) return { buf: out, method: `AES-256-CBC ${label}` };
      } catch {}
    }
    // ── AES-256-GCM (no auth tag check) ──
    try {
      const dec = crypto.createDecipheriv('aes-256-gcm', k, iv);
      dec.setAutoPadding(false);
      const out = Buffer.concat([dec.update(buf)]);
      if (isValid(out)) return { buf: out, method: `AES-256-GCM ${label}` };
    } catch {}
    // ── ChaCha20-Poly1305 ──
    if (iv.length >= 12) {
      try {
        const dec = crypto.createDecipheriv('chacha20-poly1305', k, iv.slice(0, 12));
        const out = Buffer.concat([dec.update(buf)]);
        if (isValid(out)) return { buf: out, method: `ChaCha20-Poly1305 ${label}` };
      } catch {}
    }
    // ── ChaCha20 (stream, no tag) ──
    if (iv.length >= 16) {
      try {
        const dec = crypto.createDecipheriv('chacha20', k, iv);
        const out = Buffer.concat([dec.update(buf), dec.final()]);
        if (isValid(out)) return { buf: out, method: `ChaCha20 ${label}` };
      } catch {}
    }
    // ── AES-256-CTR ──
    try {
      const dec = crypto.createDecipheriv('aes-256-ctr', k, iv);
      const out = Buffer.concat([dec.update(buf), dec.final()]);
      if (isValid(out)) return { buf: out, method: `AES-256-CTR ${label}` };
    } catch {}
    // ── RC4 (key only, no IV) ──
    try {
      const dec = crypto.createDecipheriv('rc4', k, '');
      const out = Buffer.concat([dec.update(buf), dec.final()]);
      if (isValid(out)) return { buf: out, method: `RC4 ${label}` };
    } catch {}
  }

  // ── XOR ──
  const xout = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) xout[i] = buf[i] ^ keyBuf[i % keyBuf.length];
  if (isValid(xout)) return { buf: xout, method: 'XOR' };

  return null;
}

async function findKeyBrute(sampleBuf, clk, log) {
  const entries = Object.entries(clk);
  log(`Brute-force: mencoba ${entries.length} key...`);
  for (const [id, hexKey] of entries) {
    const kb = keyToBuffer(hexKey);
    const r = tryAll(sampleBuf, kb);
    if (r) { log(`Key ditemukan! Resource ID: ${id} → ${r.method}`); return { keyBuf: kb, resId: id }; }
  }
  return null;
}

// ─── Lua deobfuscation (sederhana) ────────────────────────────────────────────
function deobfLua(src) {
  let c = src, prev = '', pass = 0;
  const pipes = [
    s => s.replace(/string\.char\s*\(([^)]+)\)/g, (m, a) => {
      const ns = a.split(',').map(x => parseInt(x.trim(), 10));
      if (ns.some(isNaN) || ns.some(n => n < 0 || n > 255)) return m;
      return JSON.stringify(ns.map(n => String.fromCharCode(n)).join(''));
    }),
    s => s.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, x =>
      x.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => {
        const ch = String.fromCharCode(parseInt(h, 16));
        return ch === '"' ? '\\"' : ch === "'" ? "\\'" : ch;
      })
    ),
    s => { let p = s, i = 0; while (p !== s || i++ < 1) { p = s; s = s.replace(/"([^"\\]*)"\s*\.\.\s*"([^"\\]*)"/g, (_, a, b) => `"${a}${b}"`); } return s; },
  ];
  do { prev = c; for (const fn of pipes) c = fn(c); pass++; } while (c !== prev && pass < 8);
  return c;
}

// ─── Keymaster API download (server-side decrypt by CFX) ─────────────────────
async function tryKeymasterDownload(jwtToken, resId, log) {
  const https = require('https');
  const endpoints = [
    `https://keymaster.fivem.net/api/resource/${resId}/archive`,
    `https://keymaster.fivem.net/api/assetsystem/resource/${resId}/versions/latest/archive`,
    `https://runtime.fivem.net/policy/resource/${resId}`,
  ];
  for (const url of endpoints) {
    try {
      log(`Mencoba keymaster: ${url}`);
      const buf = await new Promise((resolve, reject) => {
        const req = https.get(url, {
          headers: {
            'Authorization': `Bearer ${jwtToken}`,
            'User-Agent': 'CitizenFX/6 (FXServer)',
            'Accept': 'application/zip, application/octet-stream',
          },
          timeout: 15000,
        }, res => {
          if (res.statusCode === 401 || res.statusCode === 403) return reject(new Error(`HTTP ${res.statusCode}`));
          if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => resolve(Buffer.concat(chunks)));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      });
      if (buf.length > 100) {
        log(`Keymaster: dapat ${(buf.length/1024).toFixed(1)} KB dari ${url}`);
        return buf;
      }
    } catch (e) { log(`Keymaster ${url}: ${e.message}`); }
  }
  return null;
}

// ─── Main endpoint ─────────────────────────────────────────────────────────────
app.post('/decrypt', upload.fields([{ name: 'zip' }, { name: 'grant' }]), async (req, res) => {
  const logs = [];
  const log = m => { logs.push(m); console.log(m); };

  try {
    const zipBuf = req.files?.zip?.[0]?.buffer;
    const grantBuf = req.files?.grant?.[0]?.buffer;
    const keyStr = req.body?.key || '';

    if (!zipBuf) return res.status(400).json({ error: 'ZIP wajib diupload', logs });

    log(`ZIP: ${(zipBuf.length / 1024).toFixed(1)} KB`);

    const zip = await JSZip.loadAsync(zipBuf);
    const entries = Object.entries(zip.files).filter(([, f]) => !f.dir);
    log(`${entries.length} file ditemukan`);

    // Parse grants
    const grants = grantBuf ? parseGrants(grantBuf.toString('utf8')) : null;
    const isJWT = grants?.__jwt;
    const jwtClk = grants?.clk || {};
    if (grants) log(`Grants: ${isJWT ? Object.keys(jwtClk).length + ' key (JWT)' : Object.keys(grants.map || {}).length + ' key (XML/JSON)'}`);

    // Detect resource ID from fxmanifest
    let resId = '', resName = '';
    const mf = entries.find(([n]) => n.endsWith('fxmanifest.lua') || n.endsWith('__resource.lua'));
    if (mf) {
      const p = mf[0].split('/'); if (p.length > 1) resName = p[0].toLowerCase();
      const mt = await mf[1].async('string');
      const rm = mt.match(/resource_id\s*['"]?(\d+)['"]?/);
      if (rm) resId = rm[1];
      if (!resId) { const lm = mt.match(/fivem-releases\.com\/[^/]+\/(\d+)/); if (lm) resId = lm[1]; }
    }
    log(`Resource: ${resName || '(unknown)'}${resId ? ` (ID: ${resId})` : ''}`);

    // ── Try keymaster server-side download first ──────────────────────────────
    if (isJWT && resId && grantBuf) {
      const rawJWT = grantBuf.toString('utf8').trim();
      log(`Mencoba download langsung dari keymaster (resource ID: ${resId})...`);
      const kmBuf = await tryKeymasterDownload(rawJWT, resId, log);
      if (kmBuf) {
        // Check if it's a valid ZIP
        try {
          await JSZip.loadAsync(kmBuf);
          log('Keymaster berhasil — ZIP ter-decrypt diterima');
          const outName = path.basename(req.files.zip[0].originalname, '.zip') + '_km_decrypted.zip';
          res.set({
            'Content-Type': 'application/zip',
            'Content-Disposition': `attachment; filename="${outName}"`,
            'X-Decrypt-Log': logs.slice(-10).join(' | '),
          });
          return res.send(kmBuf);
        } catch { log('Keymaster: response bukan ZIP valid, lanjut decrypt lokal'); }
      }
    }

    // Resolve key
    let keyBuf = null;
    if (keyStr.trim()) {
      keyBuf = keyToBuffer(keyStr.trim());
      log(`Key dari input: ${keyBuf.length} bytes`);
    } else if (isJWT) {
      if (resId && jwtClk[resId]) {
        keyBuf = keyToBuffer(jwtClk[resId]);
        log(`JWT: key untuk ID ${resId}`);
      } else {
        const allKeys = Object.entries(jwtClk);
        if (allKeys.length === 1) { keyBuf = keyToBuffer(allKeys[0][1]); log(`JWT: single key (ID ${allKeys[0][0]})`); }
        else {
          // Brute force dengan probe file pertama
          log('Resource ID tidak di manifest — brute-force...');
          const probe = entries.find(([n]) => ['ydd','ydr','yft','ycd','ync'].includes(n.split('.').pop().toLowerCase()));
          if (probe) {
            const pb = Buffer.from(await probe[1].async('arraybuffer'));
            if (!isText(pb) && !isRSC(pb)) {
              const found = await findKeyBrute(pb, jwtClk, log);
              if (found) keyBuf = found.keyBuf;
            }
          }
          if (!keyBuf) {
            for (const [, entry] of entries) {
              const b = Buffer.from(await entry.async('arraybuffer'));
              if (!isText(b) && !isRSC(b) && b.length > 256) {
                const found = await findKeyBrute(b, jwtClk, log);
                if (found) { keyBuf = found.keyBuf; break; }
              }
            }
          }
        }
      }
    } else if (grants?.map && resName && grants.map[resName]) {
      keyBuf = keyToBuffer(grants.map[resName]);
      log(`Key dari grants untuk: ${resName}`);
    }

    // Process files
    const outZip = new JSZip();
    let decOk = 0, plain = 0, skip = 0;

    for (const [name, entry] of entries) {
      const raw = Buffer.from(await entry.async('arraybuffer'));

      if (isText(raw)) {
        const dec = deobfLua(raw.toString('utf8'));
        outZip.file(name, dec !== raw.toString('utf8') ? Buffer.from(dec) : raw);
        if (dec !== raw.toString('utf8')) { decOk++; log(`${name} → Lua deobfuscated`); }
        else plain++;
        continue;
      }

      if (isRSC(raw)) { outZip.file(name, raw); plain++; continue; }

      if (!keyBuf) { outZip.file(name, raw); skip++; log(`${name} → SKIP (tidak ada key)`); continue; }

      const result = tryAll(raw, keyBuf);
      if (result) {
        outZip.file(name, result.buf);
        decOk++;
        log(`${name} → OK (${result.method})`);
      } else {
        outZip.file(name, raw);
        skip++;
        log(`${name} → FAIL (key tidak cocok / cipher tidak dikenal)`);
      }
    }

    log(`\nSelesai: ${decOk} decrypted, ${plain} plain, ${skip} skip`);

    const outBuf = await outZip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
    const outName = path.basename(req.files.zip[0].originalname, '.zip') + '_decrypted.zip';

    res.set({
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${outName}"`,
      'X-Decrypt-Log': logs.slice(-20).join(' | '),
    });
    res.send(outBuf);

  } catch (e) {
    log(`ERROR: ${e.message}`);
    res.status(500).json({ error: e.message, logs });
  }
});

app.listen(PORT, () => console.log(`FiveM Decrypt running → http://localhost:${PORT}`));
