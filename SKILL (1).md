---
name: parallel-scanner
description: >
  Batch analyze multiple Bitcoin addresses concurrently with a concurrency-limited queue.
  Use whenever the user wants to scan many addresses at once, run bulk vulnerability
  analysis, or process a list of addresses or transactions in parallel without hammering
  APIs. Always use this skill before writing any batch scanning or queue-based analysis.
---

# Parallel Scanner Skill

## Concurrency-Limited Queue

Prevents API rate limiting by capping simultaneous requests.

```javascript
class ParallelScanner {
  constructor(concurrency = 5) {
    this.concurrency = concurrency;
    this.queue = [];
    this.running = 0;
    this.results = [];
  }

  async scan(addresses, perAddressFn, onProgress = null) {
    let completed = 0;
    const total = addresses.length;

    return new Promise((resolve) => {
      const runNext = () => {
        while (this.running < this.concurrency && this.queue.length > 0) {
          const { address, resolve: res } = this.queue.shift();
          this.running++;
          perAddressFn(address)
            .then(result => {
              completed++;
              if (onProgress) onProgress(completed, total, address, result);
              res({ address, result, error: null });
            })
            .catch(err => {
              completed++;
              if (onProgress) onProgress(completed, total, address, null, err);
              res({ address, result: null, error: err.message });
            })
            .finally(() => {
              this.running--;
              runNext();
            });
        }
        if (this.running === 0 && this.queue.length === 0) {
          resolve(this.results);
        }
      };

      for (const address of addresses) {
        this.results.push(
          new Promise(res => this.queue.push({ address, resolve: res }))
        );
      }

      if (this.queue.length === 0) { resolve([]); return; }
      runNext();
    }).then(() => Promise.all(this.results));
  }
}
```

## Full Address Scan Pipeline

```javascript
async function scanAddressBatch(addresses, options = {}) {
  const { concurrency = 5, includeUtxo = true, includeSignatures = true } = options;
  const scanner = new ParallelScanner(concurrency);

  const scanOne = async (address) => {
    // 1. Fetch transactions (multi-source-fetcher skill)
    const txs = await cachedFetch(`txs:${address}`, () => fetchAddressTxs(address));

    // 2. Extract all signatures
    const allSigs = [];
    if (includeSignatures) {
      for (const tx of txs) {
        for (const inp of tx.inputs) {
          if (inp.address !== address) continue;
          const sig = extractSignature(inp.sigscript); // signature-extraction skill
          if (sig) allSigs.push({ ...sig, txid: tx.txid, inputIndex: tx.inputs.indexOf(inp) });
        }
      }
    }

    // 3. Run nonce reuse scan
    const nonceFindings = scanForNonceReuse(allSigs); // nonce-reuse-detector skill

    // 4. UTXO reconstruction
    const utxo = includeUtxo ? buildUTXOSet(txs) : null; // utxo-reconstruction skill

    // 5. Entropy analysis
    const entropyFindings = detectBias(allSigs); // weak-entropy-detector skill

    // 6. Score findings
    const allFindings = [...nonceFindings, ...entropyFindings];
    const score = scoreFindings(allFindings); // vulnerability-scoring skill

    return {
      address,
      txCount: txs.length,
      signatureCount: allSigs.length,
      score,
      findings: allFindings,
      utxo: utxo ? summarizeAddress(address, utxo) : null
    };
  };

  const results = await scanner.scan(
    addresses, scanOne,
    (done, total, addr) => console.log(`[${done}/${total}] Scanned: ${addr}`)
  );

  return {
    totalAddresses: addresses.length,
    completed: results.filter(r => !r.error).length,
    failed: results.filter(r => r.error).length,
    critical: results.filter(r => r.result?.score?.level === 'CRITICAL').length,
    results
  };
}
```

## Batch Report
```javascript
function summarizeBatch(scanResults) {
  const { results } = scanResults;
  return {
    summary: scanResults,
    byRisk: {
      critical: results.filter(r => r.result?.score?.level === 'CRITICAL').map(r => r.address),
      high:     results.filter(r => r.result?.score?.level === 'HIGH').map(r => r.address),
      medium:   results.filter(r => r.result?.score?.level === 'MEDIUM').map(r => r.address),
      low:      results.filter(r => r.result?.score?.level === 'LOW').map(r => r.address),
    }
  };
}
```

Pass to `structured-json-reporter` for final machine-readable output.
