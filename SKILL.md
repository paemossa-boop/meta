---
name: multi-input-correlation
description: >
  Analyze signatures across same-transaction inputs to detect same-pubkey patterns,
  cross-input signature relationships, and multi-input vulnerabilities. Use whenever
  the user wants to correlate inputs within a transaction, detect address clustering,
  find shared keys across inputs, or analyze spending patterns that reveal wallet
  ownership. Always use this skill before writing cross-input analysis code.
---

# Multi-Input Correlation Skill

## Core Analysis Pipeline

Given a transaction with multiple inputs, this skill:
1. Groups inputs by public key / address
2. Checks for shared nonces across same-key inputs
3. Detects known-linear nonce relations
4. Identifies wallet fingerprints from signing patterns

---

## Same-Pubkey Grouping

```javascript
function groupInputsByPubkey(inputs) {
  const groups = new Map();
  for (const inp of inputs) {
    const sig = extractSignature(inp.sigscript); // signature-extraction skill
    const key = sig.pubkey.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ ...inp, sig });
  }
  // Only return groups with 2+ inputs (same key used multiple times)
  return [...groups.entries()]
    .filter(([, inps]) => inps.length > 1)
    .map(([pubkey, inps]) => ({ pubkey, inputs: inps, count: inps.length }));
}
```

---

## Cross-Input Nonce Analysis

For each group of same-pubkey inputs, run all pairwise checks:

```javascript
async function analyzeGroup(group, sighashBuilder) {
  const { pubkey, inputs } = group;
  const sigs = [];

  // Compute z for each input
  for (const inp of inputs) {
    const z = await sighashBuilder.compute(inp); // sighash-builder skill
    sigs.push({ r: inp.sig.r, s: inp.sig.s, z, inputIndex: inp.index });
  }

  const findings = [];

  // Pairwise checks
  for (let i = 0; i < sigs.length; i++) {
    for (let j = i + 1; j < sigs.length; j++) {
      const a = sigs[i], b = sigs[j];

      // 1. Direct nonce reuse
      if (a.r === b.r) {
        findings.push({ type: 'NONCE_REUSE', severity: 'CRITICAL',
          pair: [a.inputIndex, b.inputIndex] });
        continue;
      }

      // 2. Linear relation check: k2 = a*k1 + b
      // Test common relations: k2=k1/2, k2=2*k1, k2=k1+c
      const relations = checkLinearRelations(a, b);
      if (relations.length > 0) {
        findings.push({ type: 'LINEAR_NONCE_RELATION', severity: 'CRITICAL',
          pair: [a.inputIndex, b.inputIndex], relations });
      }

      // 3. S-value relationship (same S → same k is likely)
      if (a.s === b.s) {
        findings.push({ type: 'SAME_S_VALUE', severity: 'HIGH',
          pair: [a.inputIndex, b.inputIndex] });
      }
    }
  }

  return { pubkey, signatureCount: sigs.length, findings };
}
```

---

## Linear Relation Checker

Tests the most common nonce relations that appear in real-world wallet vulnerabilities:

```javascript
const n = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
function mod(x) { return ((x % n) + n) % n; }
function modinv(a, m) {
  a = mod(a); let [or,r]=[a,m],[os,s]=[1n,0n];
  while(r){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}
  return mod(os);
}

function checkLinearRelations(sigA, sigB) {
  const r1=BigInt('0x'+sigA.r), s1=BigInt('0x'+sigA.s), z1=BigInt('0x'+sigA.z);
  const r2=BigInt('0x'+sigB.r), s2=BigInt('0x'+sigB.s), z2=BigInt('0x'+sigB.z);
  const found = [];

  // Helper: try to recover d given k2 = (a*k1 + b)
  function tryRecover(a, b, label) {
    try {
      // s1*k1 = z1 + r1*d  ... (1)
      // s2*(a*k1+b) = z2 + r2*d  ... (2)
      // From (2): a*s2*k1 = z2 + r2*d - s2*b
      // Multiply (1) by a*s2*s1^-1: a*s2*k1 = (z1+r1*d)*a*s2*s1^-1
      // Set equal and solve for d:
      const invS1 = modinv(s1, n);
      const A = mod(a * s2 % n * invS1);
      const num = mod(A*z1 - z2 + s2*b);  // corrected sign
      const den = mod(r2 - A*r1);
      if (den === 0n) return;
      const d = mod(num * modinv(den, n));
      const k1 = mod((z1 + r1*d) * modinv(s1, n));
      // Verify both sigs
      const checkA = mod(s1*k1) === mod(z1 + r1*d);
      const k2_exp = mod(a*k1 + b);
      const checkB = mod(s2*k2_exp) === mod(z2 + r2*d);
      if (checkA && checkB) {
        found.push({ relation: label, d: d.toString(16).padStart(64,'0'), k1: k1.toString(16).padStart(64,'0') });
      }
    } catch {}
  }

  tryRecover(1n, 0n,   'k2 = k1');        // nonce reuse (redundant but complete)
  tryRecover(modinv(2n,n), 0n, 'k2 = k1/2'); // half nonce
  tryRecover(2n, 0n,   'k2 = 2*k1');      // double nonce
  tryRecover(3n, 0n,   'k2 = 3*k1');
  tryRecover(1n, 1n,   'k2 = k1 + 1');    // off-by-one
  // For unknown constant offset: detect via (k1-k2) relation
  const diffNum = mod(2n*s1*z2 - s2*z1);
  const diffDen = mod(s2*r1 - 2n*s1*r2);
  if (diffDen !== 0n) {
    // Already handled as half-nonce in ecdsa-crypto skill — just flag
  }

  return found;
}
```

---

## Wallet Fingerprinting

Common-input-ownership heuristic: if multiple addresses sign in the same transaction,
they are likely controlled by the same wallet.

```javascript
function clusterByTransaction(transactions) {
  const clusters = new Map(); // address → cluster_id
  let nextId = 0;

  for (const tx of transactions) {
    const inputAddresses = tx.inputs.map(i => i.address).filter(Boolean);
    if (inputAddresses.length < 2) continue;

    // Find existing clusters for any of these addresses
    const existingIds = [...new Set(
      inputAddresses.map(a => clusters.get(a)).filter(id => id !== undefined)
    )];

    const clusterId = existingIds.length > 0 ? existingIds[0] : nextId++;

    // Merge all matching clusters + assign new addresses
    for (const addr of inputAddresses) {
      clusters.set(addr, clusterId);
    }
    // Merge other cluster IDs into this one
    for (const oldId of existingIds.slice(1)) {
      for (const [addr, id] of clusters) {
        if (id === oldId) clusters.set(addr, clusterId);
      }
    }
  }

  // Invert: cluster_id → [addresses]
  const result = new Map();
  for (const [addr, id] of clusters) {
    if (!result.has(id)) result.set(id, []);
    result.get(id).push(addr);
  }
  return [...result.values()].filter(c => c.length > 1);
}
```

---

## Output Format

```javascript
{
  inputCount: Number,
  sharedPubkeyGroups: [
    {
      pubkey: String,
      signatureCount: Number,
      findings: [{ type, severity, pair, relations? }]
    }
  ],
  addressClusters: [[address, ...], ...],
  overallRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}
```

Feed all findings to `vulnerability-scoring` skill.
Feed recovered keys to `structured-json-reporter` skill.
