---
name: der-mutation-playground
description: >
  Generate and test malformed DER signatures for security research and library testing.
  Use whenever the user wants to create High-S variants, apply padding modifications,
  introduce structural corruption, generate mutation test suites, or explore what
  malformed signatures look like at the byte level. Always use this skill for any
  DER signature mutation or corruption task.
---

# DER Mutation Playground Skill

## Mutation Engine

Takes a valid DER signature and produces a catalog of mutations, each targeting a
different byte-level property.

```javascript
function mutationPlayground(validSigHex) {
  const buf = Buffer.from(validSigHex, 'hex');
  const sighash = buf[buf.length - 1];
  const der = buf.slice(0, -1);

  // Parse positions
  const rLen = der[3];
  const rStart = 4;
  const sTagPos = rStart + rLen;
  const sLen = der[sTagPos + 1];
  const sStart = sTagPos + 2;

  const mutations = [];
  const add = (name, category, mutFn, expectedBehavior) => {
    try {
      const mutated = mutFn(Buffer.from(der));
      const full = Buffer.concat([mutated, Buffer.from([sighash])]);
      mutations.push({ name, category, hex: full.toString('hex'), expectedBehavior, byteLength: full.length });
    } catch(e) {
      mutations.push({ name, category, hex: null, error: e.message, expectedBehavior });
    }
  };

  // ── Category: Structural ──────────────────────────────────────────
  add('flip_sequence_tag', 'structural', (d) => { d[0] = 0x31; return d; }, 'reject');
  add('zero_total_length', 'structural', (d) => { d[1] = 0x00; return d; }, 'reject');
  add('overlong_total_length', 'structural', (d) => { d[1]++; return d; }, 'reject_or_accept_berlib');
  add('short_total_length', 'structural', (d) => { d[1]--; return d; }, 'reject');
  add('long_form_seq_0x81', 'structural', (d) => {
    const body = d.slice(2);
    return Buffer.concat([Buffer.from([0x30, 0x81, d[1]]), body]);
  }, 'accept_berlib_reject_strict');

  // ── Category: R field ─────────────────────────────────────────────
  add('flip_r_tag', 'r_field', (d) => { d[2] = 0x03; return d; }, 'reject');
  add('r_len_zero', 'r_field', (d) => { d[3] = 0x00; d[1] -= rLen; return d; }, 'reject');
  add('r_len_plus1', 'r_field', (d) => { d[3]++; d[1]++; return d; }, 'reject_or_accept_berlib');
  add('r_extra_leading_zero', 'r_field', (d) => {
    const before = d.slice(0, 3);
    const after  = d.slice(rStart);
    const newR   = Buffer.concat([Buffer.from([0x00]), d.slice(rStart, rStart + rLen)]);
    const result = Buffer.concat([before, Buffer.from([rLen + 1]), newR, after]);
    result[1]++;
    return result;
  }, 'accept_berlib_reject_strict');
  add('r_set_high_bit', 'r_field', (d) => { d[rStart] |= 0x80; return d; }, 'reject');
  add('r_clear_all', 'r_field', (d) => { d.fill(0, rStart, rStart + rLen); return d; }, 'reject');
  add('r_set_to_n', 'r_field', (d) => {
    const nBytes = Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex');
    nBytes.copy(d, rStart, 0, Math.min(rLen, 32));
    return d;
  }, 'reject');

  // ── Category: S field ─────────────────────────────────────────────
  add('flip_s_tag', 's_field', (d) => { d[sTagPos] = 0x03; return d; }, 'reject');
  add('s_len_zero', 's_field', (d) => { d[sTagPos+1] = 0x00; d[1] -= sLen; return d; }, 'reject');
  add('s_extra_leading_zero', 's_field', (d) => {
    const before = d.slice(0, sTagPos + 1);
    const sData  = d.slice(sStart, sStart + sLen);
    const after  = d.slice(sStart + sLen);
    const result = Buffer.concat([before, Buffer.from([sLen + 1, 0x00]), sData, after]);
    result[1]++;
    return result;
  }, 'accept_berlib_reject_strict');
  add('s_high_s_flip', 's_field', (d) => {
    const n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const sVal = BigInt('0x' + d.slice(sStart, sStart + sLen).toString('hex'));
    const flipped = (n - sVal).toString(16).padStart(64, '0');
    Buffer.from(flipped, 'hex').copy(d, sStart);
    return d;
  }, 'accept_math_reject_policy');

  // ── Category: Trailing data ───────────────────────────────────────
  add('trailing_zero', 'trailing', (d) => Buffer.concat([d, Buffer.from([0x00])]), 'accept_berlib_reject_strict');
  add('trailing_sequence', 'trailing', (d) => Buffer.concat([d, Buffer.from([0x30, 0x00])]), 'reject');
  add('double_sig', 'trailing', (d) => Buffer.concat([d, d.slice(2)]), 'reject');

  return {
    original: validSigHex,
    mutationCount: mutations.length,
    mutations,
    categories: [...new Set(mutations.map(m => m.category))]
  };
}
```

## Expected Behavior Legend

| Value | Meaning |
|-------|---------|
| `reject` | All correct implementations should reject |
| `accept_berlib_reject_strict` | BER-lenient libraries accept; strict DER libraries reject |
| `accept_math_reject_policy` | Mathematically valid but rejected by policy (e.g. High-S) |
| `reject_or_accept_berlib` | Implementation-dependent |

Pass mutations to `acceptance-tester` skill to verify actual library behavior.
