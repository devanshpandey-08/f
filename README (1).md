# Reproduction probes — @opensea/tool-sdk v0.29.0 payment-chain findings

Companion to `FINDINGS-tool-sdk-payment-chain.md` (Part 2) and the uploaded
`FINDINGS-tool-sdk-manifest-validation (4).md` (Part 1, which contains the
manifest-schema probes 01–06 inline in its §11 Reproduction section).

## Setup (nothing here contacts any remote service at run time)

```bash
mkdir -p /tmp/p2 && cd /tmp/p2
cat > package.json <<'EOF'
{ "name":"p2","private":true,"type":"module","version":"1.0.0" }
EOF
npm i @opensea/tool-sdk@0.29.0
cp <this dir>/07-critical-chain.mjs .
node 07-critical-chain.mjs
```

Expected output is archived verbatim in `07-critical-chain-output.txt`
(ports and the ~10-minute `validBefore` timestamps vary per run).

## Safety discipline of these probes

- Victim key is a throwaway derived from `0x1111…11`; it holds no funds and
  every signature stays on `127.0.0.1` loopback servers.
- The usage-report destination is a **local** aggregator server. The SDK's own
  `isSecureAggregatorUrl` deliberately permits `http://127.0.0.1`, so the real
  `https://api.opensea.io/api/v2/tools/usage` is never contacted. No report,
  probe, or canary in this research touches OpenSea infrastructure.
- No chain interaction: authorizations are captured and decoded off the wire,
  never submitted. Nothing settles.

## What each scenario proves (see report §3–§8 for analysis)

| Scenario | Claim |
| --- | --- |
| S1 | A 302 after the signed request forwards the `X-PAYMENT` bearer authorization cross-origin to an arbitrary host; `paidFetch` hands that host's response back as the tool result. |
| S2 | A 302 on the probe retargets the payment to a host the caller never chose, and the caller-side usage report carries the attacker-supplied `tx_hash` plus `tool_endpoint` naming the *original* origin. |
| S3 | `X402PaymentError.settled` is computed purely from server-controlled response headers — identical on-chain reality, opposite SDK advice; the "likely not settled" branch invites the double charge. |
| S4 | `paidAuthenticatedFetch` has the same redirect leak for the paid authorization, after a zero-value identity authorization. |
| S5 | With default options `paidFetch` signs any amount (incl. `2^256-1`) to any non-burn recipient on any known network; signature recovery proves the authorization is genuinely victim-signed and submittable. |

## Source-line evidence

The package ships full `sourcesContent` source maps. Recover the TypeScript:

```bash
node - <<'EOF'
import fs from 'node:fs'; import path from 'node:path';
const dist = '/tmp/p2/node_modules/@opensea/tool-sdk/dist';
function walk(d){let r=[];for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory())r=r.concat(walk(p));else if(e.name.endsWith('.map'))r.push(p);}return r;}
let seen=new Set(), n=0;
for (const mapf of walk(dist)) {
  const m = JSON.parse(fs.readFileSync(mapf,'utf8'));
  if (!m.sources?.length || !m.sourcesContent) continue;
  m.sources.forEach((s,i)=>{ const c=m.sourcesContent[i]; if(c==null) return;
    const fp=path.join('/tmp/src', s.replace(/^(\.\.\/)+/,'').replace(/^\//,''));
    if(seen.has(fp))return; seen.add(fp);
    fs.mkdirSync(path.dirname(fp),{recursive:true}); fs.writeFileSync(fp,c); n++; });
}
console.log('recovered', n, 'files -> /tmp/src');
EOF
```

14 maps → 64 `.ts` files. All `file:line` citations in the report refer to
those recovered sources (identical content to the repo at publish time).
