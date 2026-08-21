---
name: acceptance-tester
description: >
  Verify library behavior with mutated signatures — test which crypto libraries
  accept or reject specific signature variants. Use whenever the user wants to
  build an expected vs actual acceptance matrix, automatically detect library bugs,
  test CVE-2024-42461 exposure, or verify DER mutation behavior across elliptic,
  noble-secp256k1, and bitcoinjs-lib. Always use this skill for any multi-library
  signature acceptance testing task.
---

# Acceptance Tester Skill

## Test Runner

```javascript
async function runAcceptanceMatrix(pubkeyHex, msgHashHex, mutations) {
  const results = [];

  for (const mut of mutations) {
    if (!mut.hex) {
      results.push({ name: mut.name, skipped: true, reason: mut.error });
      continue;
    }

    const row = {
      name: mut.name,
      category: mut.category,
      hex: mut.hex,
      expectedBehavior: mut.expectedBehavior,
      results: {},
      bugs: []
    };

    // Test each library
    row.results['elliptic']        = await testElliptic(pubkeyHex, msgHashHex, mut.hex);
    row.results['noble-secp256k1'] = await testNoble(pubkeyHex, msgHashHex, mut.hex);
    row.results['bitcoinjs-lib']   = await testBitcoinjsLib(pubkeyHex, msgHashHex, mut.hex);

    // Detect discrepancies
    row.bugs = detectBugs(row.results, mut.expectedBehavior, mut.name);
    results.push(row);
  }

  return buildMatrix(results);
}
```

## Per-Library Testers

```javascript
async function testElliptic(pubHex, msgHex, sigHex) {
  try {
    const { ec } = require('elliptic');
    const curve = new ec('secp256k1');
    const key = curve.keyFromPublic(pubHex, 'hex');
    const derOnly = sigHex.slice(0, -2); // strip sighash byte
    const result = key.verify(msgHex, derOnly);
    return { accepted: result, error: null };
  } catch(e) {
    return { accepted: false, error: e.message };
  }
}

async function testNoble(pubHex, msgHex, sigHex) {
  try {
    const secp = require('@noble/secp256k1');
    const sig = secp.Signature.fromDER(sigHex.slice(0, -2));
    const valid = secp.verify(sig, msgHex, pubHex, { strict: true });
    return { accepted: valid, error: null };
  } catch(e) {
    return { accepted: false, error: e.message };
  }
}

async function testBitcoinjsLib(pubHex, msgHex, sigHex) {
  try {
    const ecc = require('tiny-secp256k1');
    const pubkey = Buffer.from(pubHex, 'hex');
    const hash   = Buffer.from(msgHex, 'hex');
    const sig    = Buffer.from(sigHex.slice(0, -2), 'hex');
    const result = ecc.verify(hash, pubkey, sig);
    return { accepted: result, error: null };
  } catch(e) {
    return { accepted: false, error: e.message };
  }
}
```

## Bug Detection

```javascript
function detectBugs(results, expectedBehavior, testName) {
  const bugs = [];

  const accepted = (lib) => results[lib]?.accepted === true;

  if (expectedBehavior === 'reject') {
    // All libraries should reject
    for (const [lib, res] of Object.entries(results)) {
      if (res.accepted) bugs.push({ lib, issue: `Accepted signature that should be rejected: ${testName}` });
    }
  }

  if (expectedBehavior === 'accept_berlib_reject_strict') {
    // noble and bitcoinjs-lib should reject; elliptic might accept (pre-6.5.7 bug)
    if (accepted('noble-secp256k1')) bugs.push({ lib: 'noble-secp256k1', issue: `Accepted BER variant (should be strict): ${testName}` });
    if (accepted('bitcoinjs-lib'))   bugs.push({ lib: 'bitcoinjs-lib',   issue: `Accepted BER variant (should be strict): ${testName}` });
    if (accepted('elliptic')) bugs.push({
      lib: 'elliptic',
      issue: `CVE-2024-42461 candidate: elliptic accepted BER variant: ${testName}`,
      cve: 'CVE-2024-42461'
    });
  }

  return bugs;
}
```

## Matrix Builder

```javascript
function buildMatrix(results) {
  const libraries = ['elliptic', 'noble-secp256k1', 'bitcoinjs-lib'];
  const allBugs = results.flatMap(r => r.bugs ?? []);

  return {
    totalTests: results.length,
    passed: results.filter(r => r.bugs?.length === 0 && !r.skipped).length,
    bugsFound: allBugs.length,
    cveExposures: allBugs.filter(b => b.cve).length,
    matrix: results.map(r => ({
      test: r.name,
      category: r.category,
      expected: r.expectedBehavior,
      ...Object.fromEntries(libraries.map(lib => [
        lib, r.results?.[lib]?.accepted === true ? '✓ accept' :
             r.results?.[lib]?.accepted === false ? '✗ reject' : 'error'
      ])),
      bugs: r.bugs?.length > 0 ? r.bugs.map(b => b.issue).join('; ') : ''
    })),
    bugDetails: allBugs
  };
}
```

## Output

Print matrix as table + JSON for `structured-json-reporter`.
Highlight any row where `elliptic` accepts but others reject — CVE-2024-42461 exposure.
