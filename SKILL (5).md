---
name: script-type-detector
description: >
  Identify Bitcoin script patterns from raw scriptPubKey and scriptSig hex.
  Use whenever the user wants to classify script types, detect P2PKH, P2WPKH,
  P2SH, P2WSH, P2TR, multisig, or non-standard scripts, or route a script to
  the correct parsing/sighash logic. Always use this skill before writing
  script classification code.
---

# Script Type Detector Skill

## scriptPubKey Pattern Matching

```javascript
function detectScriptType(scriptPubKeyHex) {
  const s = scriptPubKeyHex.toLowerCase();
  const len = s.length;

  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  if (/^76a914[0-9a-f]{40}88ac$/.test(s))
    return { type: 'P2PKH', hashHex: s.slice(6, 46) };

  // P2SH: OP_HASH160 <20> OP_EQUAL
  if (/^a914[0-9a-f]{40}87$/.test(s))
    return { type: 'P2SH', hashHex: s.slice(4, 44) };

  // P2PK: <33-byte-compressed-pubkey> OP_CHECKSIG
  if (/^21(02|03)[0-9a-f]{64}ac$/.test(s))
    return { type: 'P2PK', pubkeyHex: s.slice(2, 68) };

  // P2PK: <65-byte-uncompressed-pubkey> OP_CHECKSIG
  if (/^4104[0-9a-f]{128}ac$/.test(s))
    return { type: 'P2PK_UNCOMPRESSED', pubkeyHex: s.slice(2, 132) };

  // P2WPKH: OP_0 <20>
  if (/^0014[0-9a-f]{40}$/.test(s))
    return { type: 'P2WPKH', hashHex: s.slice(4, 44) };

  // P2WSH: OP_0 <32>
  if (/^0020[0-9a-f]{64}$/.test(s))
    return { type: 'P2WSH', hashHex: s.slice(4, 68) };

  // P2TR (Taproot): OP_1 <32>
  if (/^5120[0-9a-f]{64}$/.test(s))
    return { type: 'P2TR', tweakedPubkeyHex: s.slice(4, 68) };

  // OP_RETURN (data carrier)
  if (s.startsWith('6a'))
    return { type: 'OP_RETURN', data: s.slice(4) };

  // Bare multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
  const msig = detectBareMultisig(s);
  if (msig) return msig;

  return { type: 'NONSTANDARD', raw: s };
}

function detectBareMultisig(s) {
  // OP_1..OP_16 = 0x51..0x60
  const mOp = parseInt(s.slice(0, 2), 16);
  if (mOp < 0x51 || mOp > 0x60) return null;
  const m = mOp - 0x50;
  // Parse pubkeys (21 or 41 bytes each)
  const pubkeys = [];
  let pos = 2;
  while (pos < s.length - 4) {
    const plen = parseInt(s.slice(pos, pos+2), 16);
    if (plen !== 0x21 && plen !== 0x41) break;
    pubkeys.push(s.slice(pos+2, pos+2+(plen*2)));
    pos += 2 + plen*2;
  }
  const nOp = parseInt(s.slice(pos, pos+2), 16);
  if (nOp < 0x51 || nOp > 0x60) return null;
  const n = nOp - 0x50;
  if (s.slice(pos+2) !== 'ae') return null;
  if (pubkeys.length !== n) return null;
  return { type: `P2MS_${m}_OF_${n}`, m, n, pubkeys };
}
```

## scriptSig Type Detection

```javascript
function detectScriptSigType(scriptSigHex) {
  const s = scriptSigHex.toLowerCase();

  // Empty → SegWit native (witness carries data)
  if (s === '' || s === '00') return { type: 'SEGWIT_NATIVE' };

  // P2PKH: <sig> <pubkey>
  if (/^47|48[0-9a-f]+21(02|03)[0-9a-f]{64}$/.test(s) ||
      /^47|48[0-9a-f]+4104[0-9a-f]{128}$/.test(s))
    return { type: 'P2PKH_SCRIPTSIG' };

  // P2SH-P2WPKH: just the witness program push
  if (/^160014[0-9a-f]{40}$/.test(s))
    return { type: 'P2SH_P2WPKH_SCRIPTSIG', witnessProgram: s.slice(4) };

  // P2SH multisig: OP_0 <sigs> <redeemScript>
  if (s.startsWith('00'))
    return { type: 'P2SH_MULTISIG_SCRIPTSIG' };

  return { type: 'UNKNOWN_SCRIPTSIG' };
}
```

## Routing Table

After detection, route to the correct skill:

| Script Type | Sighash Algorithm | Sig Location | Skill |
|-------------|-------------------|--------------|-------|
| P2PKH | Legacy | scriptSig | `sighash-builder` (legacy) |
| P2PK | Legacy | scriptSig | `sighash-builder` (legacy) |
| P2SH | Legacy | scriptSig (redeemScript) | `sighash-builder` (legacy) |
| P2WPKH | BIP143 | witness[0] | `sighash-builder` (BIP143) |
| P2WSH | BIP143 | witness[...] | `sighash-builder` (BIP143) |
| P2SH-P2WPKH | BIP143 | witness[0] | `sighash-builder` (BIP143) |
| P2TR (key path) | BIP341 | witness[0] | Taproot sighash (future skill) |
| P2MS bare | Legacy | scriptSig | `sighash-builder` (legacy) |

## Output
```javascript
{
  scriptType: String,
  sigLocation: 'scriptSig' | 'witness' | 'both',
  sighashAlgorithm: 'legacy' | 'bip143' | 'bip341',
  extractedFields: {}   // type-specific fields
}
```
