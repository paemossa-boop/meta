---
name: tor-enhanced-fetcher
description: >
  Privacy-preserving blockchain data queries via Tor/SOCKS5 proxy. Use whenever
  the user needs anonymous blockchain queries, wants to avoid IP-based tracking
  by block explorers, needs SOCKS5 proxy support, or is building a privacy-sensitive
  analysis pipeline. Includes exponential backoff and global throttling.
---

# Tor-Enhanced Fetcher Skill

## Architecture

Requests route through a local SOCKS5 proxy (Tor default: 127.0.0.1:9050).
Each request uses a fresh circuit where possible to prevent correlation.

## Node.js Implementation

```javascript
const SocksProxyAgent = require('socks-proxy-agent');

class TorFetcher {
  constructor(options = {}) {
    this.proxyUrl  = options.proxyUrl  ?? 'socks5://127.0.0.1:9050';
    this.minDelay  = options.minDelay  ?? 2000;  // ms between requests
    this.maxDelay  = options.maxDelay  ?? 60000;
    this.lastReq   = 0;
    this.agent     = new SocksProxyAgent(this.proxyUrl);
  }

  async throttle() {
    const wait = this.lastReq + this.minDelay - Date.now();
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    this.lastReq = Date.now();
  }

  async fetch(url, maxRetries = 4) {
    let delay = 2000;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        await this.throttle();
        const res = await fetch(url, {
          agent: this.agent,
          signal: AbortSignal.timeout(15000),
          headers: { 'User-Agent': 'Mozilla/5.0' } // blend in
        });
        if (res.status === 429) {
          // Rate limited — backoff aggressively
          await new Promise(r => setTimeout(r, Math.min(delay * 2, this.maxDelay)));
          delay = Math.min(delay * 2, this.maxDelay);
          continue;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res;
      } catch(err) {
        if (attempt === maxRetries - 1) throw err;
        await new Promise(r => setTimeout(r, delay));
        delay = Math.min(delay * 2, this.maxDelay);
      }
    }
  }

  async fetchTx(txid) {
    // Use .onion endpoints when available for maximum privacy
    const endpoints = [
      `http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/api/tx/${txid}`,
      `https://blockstream.info/api/tx/${txid}`,
      `https://mempool.space/api/tx/${txid}`
    ];
    for (const url of endpoints) {
      try {
        const res = await this.fetch(url);
        return await res.json();
      } catch { continue; }
    }
    throw new Error(`Cannot fetch tx ${txid} via Tor`);
  }

  async fetchRawHex(txid) {
    const endpoints = [
      `http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/api/tx/${txid}/hex`,
      `https://blockstream.info/api/tx/${txid}/hex`,
      `https://mempool.space/api/tx/${txid}/hex`
    ];
    for (const url of endpoints) {
      try {
        const res = await this.fetch(url);
        const text = await res.text();
        if (/^[0-9a-f]+$/i.test(text.trim())) return text.trim();
      } catch { continue; }
    }
    throw new Error(`Cannot fetch raw hex for ${txid} via Tor`);
  }
}
```

## Setup Requirements

```bash
# Install Tor (Ubuntu/Debian)
sudo apt install tor
sudo systemctl start tor

# Verify proxy is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Install Node.js dependency
npm install socks-proxy-agent
```

## Privacy Notes

- Each call to `new TorFetcher()` shares the same circuit unless Tor is configured with `MaxCircuitDirtiness 0`
- For maximum isolation: call `tor-control` to request new identity between address lookups
- Never mix Tor and clearnet requests for the same analysis session
- Onion services (.onion) provide end-to-end encryption without exit node visibility

## Onion Endpoints

| Service | Onion Address |
|---------|---------------|
| Blockstream Explorer | `explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion` |
| Mempool.space | `mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion` |

Drop-in replacement for `multi-source-fetcher` when privacy is required.
