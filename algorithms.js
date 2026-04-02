/**
 * CipherLab — algorithms.js
 * All encryption / decryption / hashing logic lives here.
 */

const AlgoMeta = {
  aes: {
    info: '<span>AES-256</span> — Advanced Encryption Standard. Military-grade symmetric encryption using a <span>secret key</span>. Most widely used cipher in the world today.',
    keys: [{ id: 'aes-key', label: 'Secret Key', type: 'password', placeholder: 'Enter a strong secret key...' }]
  },
  caesar: {
    info: '<span>Caesar Cipher</span> — Classic substitution cipher. Each letter is shifted by a fixed <span>number (1–25)</span>. Easy to break but great for learning fundamentals.',
    keys: [{ id: 'caesar-shift', label: 'Shift Value (1–25)', type: 'text', placeholder: '3' }]
  },
  vigenere: {
    info: '<span>Vigenere Cipher</span> — Polyalphabetic substitution cipher. Uses a <span>keyword</span> to shift each letter differently. Much stronger than Caesar alone.',
    keys: [{ id: 'vig-key', label: 'Keyword', type: 'text', placeholder: 'SECRET' }]
  },
  base64: {
    info: '<span>Base64</span> — Encoding scheme (not encryption) converting binary data to ASCII text. Widely used in data transfer, APIs, and email attachments. <span>No key needed.</span>',
    keys: []
  },
  rot13: {
    info: '<span>ROT-13</span> — Rotates each letter by exactly 13 positions. Applying it twice restores the original text. <span>No key needed.</span> Symmetric by design.',
    keys: []
  },
  xor: {
    info: '<span>XOR Cipher</span> — Bitwise XOR of each character with a repeating key. Foundation of many modern ciphers. Same operation both encrypts and decrypts.',
    keys: [{ id: 'xor-key', label: 'XOR Key', type: 'text', placeholder: 'mykey123' }]
  }
};

// ─── AES ───────────────────────────────────────────────────────────────────

function aesEncrypt(text, key) {
  if (!key) throw new Error('AES requires a secret key');
  return CryptoJS.AES.encrypt(text, key).toString();
}

function aesDecrypt(cipher, key) {
  if (!key) throw new Error('AES requires a secret key');
  const bytes  = CryptoJS.AES.decrypt(cipher, key);
  const result = bytes.toString(CryptoJS.enc.Utf8);
  if (!result) throw new Error('Decryption failed — wrong key or corrupted data');
  return result;
}

// ─── Caesar ────────────────────────────────────────────────────────────────

function caesarShift(text, shift) {
  shift = ((shift % 26) + 26) % 26;
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c >= 'a' ? 97 : 65;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function caesarEncrypt(text, shift) { return caesarShift(text, shift); }
function caesarDecrypt(text, shift) { return caesarShift(text, 26 - ((shift % 26 + 26) % 26)); }

// ─── Vigenere ──────────────────────────────────────────────────────────────

function vigenereProcess(text, keyword, mode) {
  const key = keyword.toUpperCase().replace(/[^A-Z]/g, '');
  if (!key) throw new Error('Vigenere requires a valid keyword');
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, c => {
    const base  = c >= 'a' ? 97 : 65;
    const shift = key.charCodeAt(ki % key.length) - 65;
    ki++;
    const s = mode === 'encrypt' ? shift : 26 - shift;
    return String.fromCharCode(((c.charCodeAt(0) - base + s) % 26) + base);
  });
}

function vigenereEncrypt(text, key) { return vigenereProcess(text, key, 'encrypt'); }
function vigenereDecrypt(text, key) { return vigenereProcess(text, key, 'decrypt'); }

// ─── Base64 ────────────────────────────────────────────────────────────────

function base64Encode(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function base64Decode(text) {
  try {
    return decodeURIComponent(escape(atob(text)));
  } catch {
    throw new Error('Invalid Base64 string');
  }
}

// ─── ROT-13 ────────────────────────────────────────────────────────────────

function rot13(text) {
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c >= 'a' ? 97 : 65;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

// ─── XOR ───────────────────────────────────────────────────────────────────

function xorEncrypt(text, key) {
  if (!key) throw new Error('XOR requires a key');
  let out = '';
  for (let i = 0; i < text.length; i++) {
    out += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return btoa(out);
}

function xorDecrypt(cipher, key) {
  if (!key) throw new Error('XOR requires a key');
  let decoded;
  try { decoded = atob(cipher); }
  catch { throw new Error('Invalid XOR ciphertext (expected Base64-encoded string)'); }
  let out = '';
  for (let i = 0; i < decoded.length; i++) {
    out += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

// ─── Hashing ───────────────────────────────────────────────────────────────

function computeAllHashes(text) {
  return {
    sha256: CryptoJS.SHA256(text).toString(),
    sha1:   CryptoJS.SHA1(text).toString(),
    md5:    CryptoJS.MD5(text).toString(),
    sha512: CryptoJS.SHA512(text).toString()
  };
}

// ─── Dispatcher ────────────────────────────────────────────────────────────

function runCipher(algo, mode, text, keys) {
  switch (algo) {
    case 'aes':
      return mode === 'encrypt'
        ? aesEncrypt(text, keys['aes-key'])
        : aesDecrypt(text, keys['aes-key']);

    case 'caesar': {
      const shift = parseInt(keys['caesar-shift']) || 3;
      return mode === 'encrypt'
        ? caesarEncrypt(text, shift)
        : caesarDecrypt(text, shift);
    }

    case 'vigenere':
      return mode === 'encrypt'
        ? vigenereEncrypt(text, keys['vig-key'] || 'KEY')
        : vigenereDecrypt(text, keys['vig-key'] || 'KEY');

    case 'base64':
      return mode === 'encrypt' ? base64Encode(text) : base64Decode(text);

    case 'rot13':
      return rot13(text); // same for both

    case 'xor':
      return mode === 'encrypt'
        ? xorEncrypt(text, keys['xor-key'] || 'key')
        : xorDecrypt(text, keys['xor-key'] || 'key');

    default:
      throw new Error('Unknown algorithm');
  }
}
