const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I,O,0,1

function randomSegment(len) {
  let s = '';
  const crypto = globalThis.crypto;
  if (crypto?.getRandomValues) {
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    for (let i = 0; i < len; i += 1) {
      s += CHARSET[buf[i] % CHARSET.length];
    }
    return s;
  }
  for (let i = 0; i < len; i += 1) {
    s += CHARSET[Math.floor(Math.random() * CHARSET.length)];
  }
  return s;
}

/** @returns {string} e.g. ABCD-EFGH-JKLM */
export function generateLicenseKeySegments() {
  return `${randomSegment(4)}-${randomSegment(4)}-${randomSegment(4)}`;
}
