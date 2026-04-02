/**
 * CipherLab — app.js
 * UI wiring, event handling, and DOM interactions.
 */

// ─── State ─────────────────────────────────────────────────────────────────

let currentAlgo = 'aes';

// ─── Init ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  renderAlgoUI('aes');
  bindAlgoTabs();
  bindActions();
  bindHashInput();
  bindPasswordChecker();
});

// ─── Algorithm UI ──────────────────────────────────────────────────────────

function renderAlgoUI(algo) {
  const meta = AlgoMeta[algo];
  document.getElementById('algo-info').innerHTML = meta.info;

  const keyRow = document.getElementById('key-row');
  keyRow.innerHTML = '';

  if (meta.keys.length === 0) {
    keyRow.innerHTML = '<span class="no-key-msg">No key required for this algorithm.</span>';
    return;
  }

  meta.keys.forEach(k => {
    keyRow.innerHTML += `
      <div class="field-group">
        <div class="field-label">${k.label}</div>
        <input type="${k.type}" id="${k.id}" placeholder="${k.placeholder}" autocomplete="off" />
      </div>`;
  });
}

function bindAlgoTabs() {
  document.getElementById('algo-tabs').addEventListener('click', e => {
    const btn = e.target.closest('.algo-btn');
    if (!btn) return;

    document.querySelectorAll('.algo-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    currentAlgo = btn.dataset.algo;
    renderAlgoUI(currentAlgo);
    setStatus('idle', 'Algorithm: ' + currentAlgo.toUpperCase());
  });
}

// ─── Actions ───────────────────────────────────────────────────────────────

function bindActions() {
  document.getElementById('btn-encrypt').addEventListener('click', () => process('encrypt'));
  document.getElementById('btn-decrypt').addEventListener('click', () => process('decrypt'));
  document.getElementById('btn-clear').addEventListener('click',   clearAll);
  document.getElementById('btn-swap').addEventListener('click',    swapText);
  document.getElementById('copy-btn').addEventListener('click',    copyOutput);
}

function collectKeys() {
  const keys = {};
  AlgoMeta[currentAlgo].keys.forEach(k => {
    const el = document.getElementById(k.id);
    if (el) keys[k.id] = el.value.trim();
  });
  return keys;
}

function process(mode) {
  const input = document.getElementById('input-text').value;
  if (!input.trim()) {
    setStatus('err', 'No input provided');
    return;
  }

  try {
    const keys   = collectKeys();
    const result = runCipher(currentAlgo, mode, input, keys);

    document.getElementById('output-text').value = result;
    setStatus('ok', mode === 'encrypt' ? '✔ Encrypted successfully' : '✔ Decrypted successfully');
  } catch (err) {
    document.getElementById('output-text').value = '';
    setStatus('err', err.message || 'Operation failed');
  }
}

function clearAll() {
  document.getElementById('input-text').value  = '';
  document.getElementById('output-text').value = '';
  setStatus('idle', 'Cleared.');
}

function swapText() {
  const input  = document.getElementById('input-text');
  const output = document.getElementById('output-text');
  const tmp    = input.value;
  input.value  = output.value;
  output.value = tmp;
  setStatus('idle', 'Input and output swapped.');
}

function copyOutput() {
  const val = document.getElementById('output-text').value;
  if (!val) { setStatus('err', 'Nothing to copy'); return; }
  navigator.clipboard.writeText(val)
    .then(() => setStatus('ok', '✔ Copied to clipboard!'))
    .catch(() => setStatus('err', 'Copy failed'));
}

// ─── Status Bar ────────────────────────────────────────────────────────────

function setStatus(type, msg) {
  const bar = document.getElementById('status-bar');
  bar.className = 'status-bar status-' + type;
  bar.innerHTML = `<span class="status-icon">${type === 'ok' ? '✔' : type === 'err' ? '⚠' : '○'}</span><span class="status-text">${msg}</span>`;
}

// ─── Hash Generator ────────────────────────────────────────────────────────

function bindHashInput() {
  document.getElementById('hash-input').addEventListener('input', computeHashes);

  document.querySelectorAll('.hash-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const val = document.getElementById(btn.dataset.target)?.textContent;
      if (!val || val === '—') return;
      navigator.clipboard.writeText(val).then(() => {
        btn.textContent = 'copied!';
        setTimeout(() => btn.textContent = 'copy', 1500);
      });
    });
  });
}

function computeHashes() {
  const text = document.getElementById('hash-input').value;

  if (!text) {
    ['h-sha256', 'h-sha1', 'h-md5', 'h-sha512'].forEach(id => {
      document.getElementById(id).textContent = '—';
    });
    return;
  }

  const hashes = computeAllHashes(text);
  document.getElementById('h-sha256').textContent = hashes.sha256;
  document.getElementById('h-sha1').textContent   = hashes.sha1;
  document.getElementById('h-md5').textContent    = hashes.md5;
  document.getElementById('h-sha512').textContent = hashes.sha512;
}

// ─── Password Strength Checker ─────────────────────────────────────────────

function bindPasswordChecker() {
  document.getElementById('pass-input').addEventListener('input', evaluatePassword);

  document.getElementById('eye-btn').addEventListener('click', () => {
    const input = document.getElementById('pass-input');
    input.type  = input.type === 'password' ? 'text' : 'password';
  });
}

const strengthColors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#00ffe7'];
const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

function evaluatePassword() {
  const pw = document.getElementById('pass-input').value;

  const criteria = {
    len:   pw.length >= 8,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    num:   /[0-9]/.test(pw),
    sym:   /[^A-Za-z0-9]/.test(pw)
  };

  // Update criteria items
  updateCriteria('cr-len',   criteria.len,   '✓ At least 8 characters',        '✗ At least 8 characters');
  updateCriteria('cr-upper', criteria.upper, '✓ Uppercase letter',              '✗ Uppercase letter');
  updateCriteria('cr-lower', criteria.lower, '✓ Lowercase letter',              '✗ Lowercase letter');
  updateCriteria('cr-num',   criteria.num,   '✓ Number',                        '✗ Number');
  updateCriteria('cr-sym',   criteria.sym,   '✓ Special character (!@#$...)',   '✗ Special character (!@#$...)');

  // Score
  const score = Object.values(criteria).filter(Boolean).length;
  const bars  = document.querySelectorAll('.sbar');
  bars.forEach((bar, i) => {
    bar.style.background = i < score ? strengthColors[score - 1] : 'var(--border-mid)';
  });

  const label = document.getElementById('strength-label');
  if (!pw) {
    label.textContent = 'Enter a password above';
    label.style.color = 'var(--text-muted)';
    bars.forEach(b => b.style.background = 'var(--border-mid)');
  } else {
    label.textContent = `Strength: ${strengthLabels[score - 1] || 'Very Weak'}`;
    label.style.color = strengthColors[score - 1] || strengthColors[0];
  }
}

function updateCriteria(id, pass, passText, failText) {
  const el = document.getElementById(id);
  el.textContent = pass ? passText : failText;
  el.classList.toggle('pass', pass);
}
