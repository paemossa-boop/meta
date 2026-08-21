---
name: structured-json-reporter
description: >
  Generate standardized machine-readable JSON analysis reports for SignatureFixer.
  Use whenever the user wants a final analysis report, machine-readable output,
  structured results for integration, or a complete summary of all vulnerability
  findings from a scan session. Always use this as the last step in any analysis pipeline.
---

# Structured JSON Reporter Skill

## Report Schema v1.0

```typescript
interface SignatureFixerReport {
  meta: {
    version: '1.0';
    generatedAt: string;        // ISO 8601
    scanType: 'single_tx' | 'address' | 'batch';
    subject: string;            // txid or address
  };

  summary: {
    riskScore: number;          // 0-100
    riskLevel: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    findingCount: number;
    criticalCount: number;
    recommendation: string;
  };

  transaction?: {
    txid: string;
    blockHeight: number;
    blockTime: string;          // ISO 8601
    inputCount: number;
    outputCount: number;
    totalInputBTC: string;
    totalOutputBTC: string;
    feeSatoshis: number;
  };

  signatures: SignatureResult[];
  findings: Finding[];
  recoveredKeys?: RecoveredKey[];
  utxo?: UTXOSummary;
}

interface SignatureResult {
  inputIndex: number;
  address: string;
  scriptType: string;
  r: string;                    // hex 64 chars
  s: string;                    // hex 64 chars
  z: string;                    // hex 64 chars
  pubkey: string;
  sighashType: number;
  isLowS: boolean;
  isStrictDER: boolean;
  derErrors: string[];
}

interface Finding {
  id: string;                   // e.g. "NONCE_REUSE_0_1"
  type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affectedInputs: number[];
  description: string;
  evidence: Record<string, any>;
}

interface RecoveredKey {
  address: string;
  pubkey: string;
  privateKeyHex: string;
  privateKeyDec: string;
  recoveryMethod: string;       // e.g. "nonce_reuse", "half_nonce", "linear_relation"
  verifiedAgainstSignatures: boolean;
}
```

## Report Builder

```javascript
function buildReport(scanType, subject, data) {
  const report = {
    meta: {
      version: '1.0',
      generatedAt: new Date().toISOString(),
      scanType,
      subject
    },
    summary: {
      riskScore: data.score?.score ?? 0,
      riskLevel: data.score?.level ?? 'INFO',
      findingCount: data.findings?.length ?? 0,
      criticalCount: (data.findings ?? []).filter(f => f.severity === 'CRITICAL').length,
      recommendation: data.score?.recommendation ?? ''
    }
  };

  if (data.tx) {
    report.transaction = {
      txid: data.tx.txid,
      blockHeight: data.tx.block?.height,
      blockTime: data.tx.time ? new Date(data.tx.time * 1000).toISOString() : null,
      inputCount: data.tx.inputs.length,
      outputCount: data.tx.outputs.length,
      totalInputBTC: satsToBTC(data.tx.inputs.reduce((s, i) => s + BigInt(i.value ?? 0), 0n)),
      totalOutputBTC: satsToBTC(data.tx.outputs.reduce((s, o) => s + BigInt(o.value ?? 0), 0n)),
      feeSatoshis: Number(data.tx.fee ?? 0)
    };
  }

  report.signatures = (data.signatures ?? []).map((sig, i) => ({
    inputIndex: sig.inputIndex ?? i,
    address: sig.address ?? '',
    scriptType: sig.scriptType ?? 'UNKNOWN',
    r: (sig.r ?? '').padStart(64, '0'),
    s: (sig.s ?? '').padStart(64, '0'),
    z: (sig.z ?? '').padStart(64, '0'),
    pubkey: sig.pubkey ?? '',
    sighashType: sig.sighashType ?? 1,
    isLowS: sig.isLowS ?? true,
    isStrictDER: sig.isStrictDER ?? true,
    derErrors: sig.derErrors ?? []
  }));

  report.findings = (data.findings ?? []).map((f, i) => ({
    id: `${f.type}_${i}`,
    type: f.type,
    severity: f.severity,
    affectedInputs: f.affectedInputs ?? f.pair ?? [],
    description: f.note ?? f.description ?? '',
    evidence: f.evidence ?? {}
  }));

  if (data.recoveredKeys?.length > 0) {
    report.recoveredKeys = data.recoveredKeys.map(k => ({
      address: k.address,
      pubkey: k.pubkey,
      privateKeyHex: k.d,
      privateKeyDec: k.d_dec ?? BigInt('0x' + k.d).toString(),
      recoveryMethod: k.method,
      verifiedAgainstSignatures: k.verified ?? false
    }));
  }

  if (data.utxo) report.utxo = data.utxo;

  return report;
}

function satsToBTC(sats) {
  const s = typeof sats === 'bigint' ? sats : BigInt(sats);
  return (Number(s) / 1e8).toFixed(8);
}
```

## Output Format

Always output as formatted JSON with 2-space indent:

```javascript
console.log(JSON.stringify(report, (key, val) =>
  typeof val === 'bigint' ? val.toString() : val, 2));
```

## Integration Notes

- All hex values are lowercase, no `0x` prefix
- All hex keys/r/s/z are exactly 64 characters (padded with leading zeros)
- BigInt values are serialized as decimal strings
- Timestamps are ISO 8601
- Report version field allows consumers to handle schema changes
