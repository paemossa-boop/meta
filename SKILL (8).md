---
name: signature-extraction
description: >
  Extract ECDSA signatures from Bitcoin transaction inputs across all script types.
  Use whenever the user needs to get r, s, z, pubkey values from a transaction input,
  or asks about scriptSig contents, witness data, P2PKH/P2WPKH/P2SH signature fields,
  multisig signing, or sighash type. Always use this skill before writing signature
  extraction code — it covers all script types and DER decoding exactly.
---
# Signature Extraction

## Script Type → Sig Location
| Type | Sig in | Pubkey in |
|------|--------|-----------|
| P2PKH | scriptSig push[0] | scriptSig push[1] |
| P2PK | scriptSig push[0] | scriptPubKey |
| P2WPKH | witness[0] | witness[1] |
| P2SH-P2WPKH | witness[0] | witness[1] |
| P2SH multisig | scriptSig pushes[1..m] | redeemScript |
| P2WSH multisig | witness[1..m] | witnessScript (last) |

## DER Decoder
```javascript
function decodeDER(hexWithSighash) {
  const buf = Buffer.from(hexWithSighash, 'hex');
  let i = 0;
  if(buf[i++]!==0x30) throw new Error('Not SEQUENCE');
  i++; // total len
  if(buf[i++]!==0x02) throw new Error('No r tag');
  const rLen=buf[i++];
  const r=buf.slice(i,i+rLen); i+=rLen;
  if(buf[i++]!==0x02) throw new Error('No s tag');
  const sLen=buf[i++];
  const s=buf.slice(i,i+sLen); i+=sLen;
  const sighashType=buf[i];
  const strip=(b)=>{let j=0;while(j<b.length-1&&b[j]===0)j++;return b.slice(j);};
  return { r:strip(r).toString('hex'), s:strip(s).toString('hex'), sighashType,
           rRaw:r.toString('hex'), sRaw:s.toString('hex') };
}
```

## Script Push Reader
```javascript
function readPush(buf, pos) {
  const op=buf[pos];
  if(op<=0x4b) return {data:buf.slice(pos+1,pos+1+op), nextPos:pos+1+op};
  if(op===0x4c){const l=buf[pos+1];return{data:buf.slice(pos+2,pos+2+l),nextPos:pos+2+l};}
  if(op===0x4d){const l=buf.readUInt16LE(pos+1);return{data:buf.slice(pos+3,pos+3+l),nextPos:pos+3+l};}
  throw new Error(`Unexpected opcode 0x${op.toString(16)}`);
}
function extractFromP2PKH(scriptSigHex) {
  const buf=Buffer.from(scriptSigHex,'hex');
  const sig=readPush(buf,0);
  const pub=readPush(buf,sig.nextPos);
  return { sigHex:sig.data.toString('hex'), pubkeyHex:pub.data.toString('hex'),
           ...decodeDER(sig.data.toString('hex')) };
}
```

## Sighash Types
0x01=ALL, 0x02=NONE, 0x03=SINGLE, 0x81=ALL|ANYONECANPAY, 0x82=NONE|ANYONECANPAY, 0x83=SINGLE|ANYONECANPAY

## Output per sig
`{ inputIndex, scriptType, r, s, rRaw, sRaw, sighashType, pubkey, sigHex }`

Pass to: nonce-reuse-detector (r,s,pubkey), der-ber-parser (sigHex), sighash-anomaly-scanner (sighashType), ecdsa-crypto (r,s,z).
