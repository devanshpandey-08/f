# @opensea/tool-sdk v0.29.0 — Payment-Chain Findings (Part 2)

**Date:** 2026-09-07 · **Package:** `@opensea/tool-sdk@0.29.0` (npm, current at test time) · **Companion:** `FINDINGS-tool-sdk-manifest-validation (4).md` (Part 1: manifest-schema conformance, Findings A–E)

**Everything below was demonstrated locally** against the published package, with throwaway keys, loopback-only servers, and **zero requests to OpenSea or any chain**. The usage-report destination is a local stand-in aggregator (the SDK's own `isSecureAggregatorUrl` permits `http://127.0.0.1` by design).

---

## 0. Executive summary

Part 1 answered the SSRF question (no) and proved the validator blesses manifests that ERC-8257 says MUST be rejected. This part follows the money: **what happens after a manifest is blessed, when a real payment is signed.**

The working hypothesis was: *"OpenSea consumes that invalid manifest and performs a dangerous financial operation because it trusted the validator."* The investigation confirms the hypothesis **and shows the problem is worse than hypothesized** — the dangerous financial operation does not even require an invalid manifest:

> **No code path in the SDK — library or CLI — ever binds a payment to a manifest.** `grep -rn "manifest" src/lib/client/*.ts src/cli/commands/pay.ts` returns nothing. The registered, on-chain-committed, origin-bound price is display data. The amount actually signed is whatever the endpoint demands at invocation time, and every guard that would tie the two together (`maxAmount`, `allowedRecipients`, `allowedAssets`) is opt-in and defaulted off.

The chain, link by link, all inside published code:

```
ERC-8257 registry (permissionless)
   │  manifest: pricing = $0.01 → creator          ← Part 1 Finding B: 13 of 14
   ▼                                                  pricing MUSTs unenforced
validateManifest / ToolManifestSchema  ── blesses ──┐
   │                                                │  invalid manifests pass
dry-run-gate.ts:47-63                               │  (zero-addr recipient,
   │  manifest.pricing[0] → defineToolPaywall       │   chain mismatch, 79-digit
   │  checks only NON-EMPTINESS; regex accepts      │   amounts, uppercase hex)
   ▼  uppercase hex                                ─┘
wire: endpoint issues 402 challenge                 ← challenge need not match
   │  {amount, payTo, asset, network} — server's      the manifest in ANY field
   ▼  free choice
paidFetch / paidAuthenticatedFetch / pay CLI
   │  DEFAULTS: no amount cap (CLI: static $10,
   │  not manifest-derived), no recipient allowlist
   │  (only a 2-entry burn-address blocklist),
   │  no confirmation hook, no manifest parameter
   │  → signs EIP-3009 transferWithAuthorization
   ▼  for the DEMANDED amount to the DEMANDED address
signed X-PAYMENT header (bearer instrument, ~10 min window)
   │  fetch defaults: redirect "follow", no timeout,
   │  no size cap, no origin pinning        ← Part 2 F1/F5
   ▼
telemetry: usage report POSTs server-supplied
   tx_hash as ground truth; settled-flag for
   double-charge guidance is header-derived  ← Part 2 F3/F4
```

### Findings and severities

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| **F1** | Signed EIP-3009 payment authorization (bearer instrument) is forwarded **cross-origin on HTTP redirect**; the redirect target's response is returned to the caller as the tool result | **High** | Demonstrated (S1, S4) |
| **F2** | Payment clients sign **any amount to any recipient** under defaults; no manifest binding, no price-change confirmation mechanism exists anywhere in the API — direct conflict with ERC-8257 "Pricing Staleness and Payment Safety" MUSTs | **Critical** (design-level) | Demonstrated (S5) + source |
| **F3** | Caller-side usage telemetry posts the **server-controlled `tx_hash`** to OpenSea's aggregator with format-only validation, under `tool_endpoint` = the originally-called URL even when the payment went elsewhere | **Medium** (backend-dependent ceiling) | Demonstrated (S2) |
| **F4** | `X402PaymentError.settled` — the SDK's double-charge safety signal — is computed **purely from attacker-controlled response headers** | **Medium** | Demonstrated (S3) |
| **F5** | Every fetch-hardening control (private-IP rejection, DNS re-resolution, `redirect:"manual"`, timeouts) exists **only in `cli.js`**; the library bundles that agent frameworks import have zero, and no guard is exported for reuse — violates ERC-8257 "Malicious Endpoints" MUSTs on the exact surface the ERC scopes them to | **High** | Bundle matrix + exports |
| **F6** | The official `pay` CLI **prints requirements and signs immediately** — no confirmation prompt — displays the amount in raw base units, caps at a static $10 constant unrelated to the manifest price, and offers `--max-amount unlimited` | **Medium** | Source (`pay.ts`) |

### What this means for the hypothesis

*Provable inside the SDK (this report):* the validator blesses invalid manifests (Part 1), the SDK's own gate-builder feeds `pricing[0]` through with non-emptiness checks only, the SDK's own payment clients never consult the manifest, and the SDK's own telemetry trusts the paying endpoint's word. **"Trusted the validator → dangerous financial operation" is a complete, in-package chain.**

*Requires OpenSea-backend scope (out of local reach, flagged in §11):* whether opensea.io's tools UI/agent runtime additionally renders or pays from blessed-invalid manifests (Part 1 Findings A/B impact), and how much backend verification the usage aggregator applies to caller-reported `tx_hash` values.

---

## 1. Method

Identical to Part 1 §3, extended:

- `npm i @opensea/tool-sdk@0.29.0` in a scratch project (real dependency tree: `@x402/core`, `@x402/fetch` 2.15.0, `viem` 2.31.3, `zod` 4.3.6).
- Recovered all 64 TypeScript sources from the 14 shipped `sourcesContent` source maps (`/tmp/src`). Line citations below are to those files.
- Behavioral probes run against the **compiled package**, not reconstructions: `probes/07-critical-chain.mjs` (archived output: `probes/07-critical-chain-output.txt`).
- Victim key `0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A` = throwaway (`0x11…11` private key), zero funds, never touches a chain or a remote host.
- Normative baseline: ERC-8257 (Draft, Standards Track, created 2026-04-17) — the standard this SDK exists to implement — quoted verbatim below from eips.ethereum.org/EIPS/eip-8257.

---

## 2. Background: what the signed artifact actually is

`paidFetch`'s payment is an **EIP-3009 `transferWithAuthorization`** on USDC: an EIP-712 signature over `{from, to, value, validAfter, validBefore, nonce}` with a domain binding `{name:"USD Coin", version:"2", chainId, verifyingContract}`.

Properties that matter for every finding below:

1. **Bearer instrument.** Anyone who possesses the header can submit it to the USDC contract and move the funds to `to`. Possession = ownership until the nonce is consumed.
2. **Exact-value, not an allowance.** Settlement transfers exactly `value` and **reverts on insufficient balance** — so the realistic loss ceiling from an over-large signed `value` is the victim's actual USDC balance on that chain, not `2^256-1`. (Stated plainly because the `2^256-1` probe row is often misread as an approval.)
3. **Single-use nonce** — satisfies ERC-8257's "Replay Resistance" MUST at the *protocol* level. The vulnerability surface is therefore **confidentiality of the signature**, not protocol replay (→ F1).
4. **Not bound to the tool.** The ERC: *"Agents SHOULD use EIP-712 typed structured data for payment authorizations, including the `toolId`, a monotonic nonce, a `deadline` timestamp, and the chain ID in the signed payload."* The signature binds chain + token + nonce + window — **no `toolId`, no endpoint, no resource**. Any host that receives the header can settle it; the payment is not cryptographically tied to having been delivered to the tool the caller intended to pay (→ F1, F2).
5. **~10-minute default window** observed in probes (`validBefore` ≈ now + 10 min, independent of the server's `maxTimeoutSeconds: 60`).

---

## 3. F1 — Redirect forwarding leaks the signed payment to an arbitrary host

### 3.1 The code

`paidFetch` (`src/lib/client/x402-payment.ts:238, 268-274`) issues both the probe and the paid replay through bare `fetch()` with caller pass-through options — **no `redirect` setting (defaults to `"follow"`), no origin pinning, no timeout**:

```ts
238:  const probeRes = await fetch(url, fetchOptions)
...
268:  const paidRes = await fetch(url, {
269:    ...fetchOptions,
270:    headers: {
271:      ...Object.fromEntries(new Headers(fetchOptions.headers).entries()),
272:      ...paymentHeaders,        // ← X-PAYMENT: the signed bearer instrument
273:    },
274:  })
```

`paidAuthenticatedFetch` is structurally identical (`src/lib/client/paid-authenticated-fetch.ts:133-139`).

Per the fetch spec (and undici's implementation), a 302 on the paid request is followed, and custom headers like `X-PAYMENT` are **forwarded to the redirect target** — including cross-origin targets. Only `Authorization` enjoys cross-origin stripping (and even that not from a trustworthy origin like loopback). The method also degrades POST→GET, so the tool never receives the invocation body either.

### 3.2 Demonstrated (probe S1)

Server A challenges for **$5,000** to the attacker address; upon receiving the signed `X-PAYMENT` it answers `302 Location: http://127.0.0.1:<B>/exfil`. Host B is a different origin the caller never named:

```
=== S1: 302 AFTER the paid request — X-PAYMENT forwarding ===
 caller called     : http://127.0.0.1:37543/tool
 paidFetch returned: HTTP 200 body={"served-by":"EXFIL-HOST"}  <- caller believes the tool answered
 EXFIL-HOST received: GET /exfil payment-bearing headers: [x-payment]
   x-payment -> EIP-3009 auth: to=0xdead000000000000000000000000000000000001 value=$5000 validBefore=1788762923
```

Three harms compose:

1. **Theft of the authorization.** Host B holds a submittable $5,000 `transferWithAuthorization` for ~10 minutes. (Server A also holds it — both can race to settle; single-use nonce means one wins.)
2. **Silent substitution of the tool result.** `paidFetch` returns B's `200` body to the caller as if the paid tool answered. An agent acts on output from an unrelated host it never chose — after paying.
3. **Same leak in the authenticated variant (probe S4):** after a zero-value identity authorization, the $5,000 payment header lands on the exfil host identically.

### 3.3 Realistic trigger conditions

The endpoint does not have to be fully attacker-owned:

- **Open redirect on the tool host** (OAuth redirectors, marketing link shorteners, misconfigured CDN rules) — extremely common, and here it converts "pay a tool" into "hand a wallet bearer token to a third party."
- **Compromised tool** — the docstring already concedes the server is trusted for amount/recipient; with F1 it additionally controls where the *signature* is delivered.
- **Any 3xx-injecting intermediary** (proxy, WAF, captive portal on plain-HTTP deployments).
- The probe-stage variant (S2, §5) shows redirects **before** signing retarget the payment itself: the challenge is parsed from the post-redirect origin, and the money and signature go there.

### 3.4 Normative anchor

ERC-8257 "Replay Resistance for Payment Protocols": *"A malicious endpoint could replay a signed payment authorization to drain additional funds beyond what the user approved for a single invocation."* EIP-3009's single-use nonce closes protocol replay — but the ERC's threat statement is precisely the artifact this leak hands out. Combined with the SHOULD on `toolId`-binding (§2.4), a conforming client would have made a leaked signature worthless to any other party; the SDK's signature is settleable by whoever holds it.

Note also `cli.js` carries `redirect:"manual"` **7×** for its own endpoint fetches (Part 1 §2): the authors treat redirects as dangerous when *they* fetch a manifest-provided URL — but the money-carrying library fetch follows them by default.

### 3.5 Remediation

```ts
// paid retry (and probe) — pin transport behavior:
const paidRes = await fetch(url, {
  ...fetchOptions,
  redirect: "manual",               // never auto-follow with a bearer header attached
  signal: fetchOptions.signal ?? AbortSignal.timeout(30_000),
})
// if a 3xx must be honored at all: re-run the FULL pipeline (challenge parse,
// validatePaymentRequirements, user confirmation) against the new origin and
// re-sign for it — never forward an existing X-PAYMENT across origins.
```

Defense in depth: request `resource`/`toolId` binding in the signed payload per the ERC SHOULD, so a misdelivered signature cannot be settled by the receiver.

---

## 4. F2 — The payment decision is unbound from the manifest; defaults sign anything

### 4.1 The code

`paidFetch`'s own docstring (`x402-payment.ts:208-214`) states the trust model:

```
* **Security:** `paidFetch` trusts the server's 402 response to determine
* the payment recipient, token, and amount. A compromised server can
* request payment to an attacker-controlled address or for an inflated
* amount. Use `maxAmount`, `allowedRecipients`, and `allowedAssets` to
* constrain what gets signed. By default, `asset` is validated against
* the known USDC contract address for the network, and `payTo` is
* rejected if it is the zero address or a known burn address.
```

The "known burn address" blocklist in full (`x402-payment.ts:19-22`) — the **only** default recipient screening before signing real money:

```ts
const REJECTED_ADDRESSES = new Set([
  "0x0000000000000000000000000000000000000000",
  "0x000000000000000000000000dead" — actually "0x000000000000000000000000000000000000dead",
])
```

Two entries. No manifest cross-check, no sanctions screen, no chain-of-custody from the registered `pricing[].recipient`. And the guards that do exist are **opt-in parameters with no defaults**:

- `maxAmount?: string` — unset ⇒ no cap.
- `allowedRecipients?: string[]` — unset ⇒ any non-burn address.
- `allowedAssets?: string[]` — unset ⇒ any *known USDC* for the network (incl. testnets).

**Nothing in the package ever populates them from a manifest.** The payment clients have no manifest parameter (`grep -rn "manifest" src/lib/client/*.ts` → 0 hits); `pay.ts` likewise (§7).

### 4.2 Demonstrated (probe S5)

Manifest on record (via the SDK's own `x402UsdcPricing`): **$0.01 → creator**. `paidFetch(url, { signer })` — defaults, no guards:

```
=== S5: what defaults sign (manifest says $0.01 -> creator) ===
honest $0.01 (matches manifest)    SIGNED value=10000            to=0xabcdef01 chain-token=0x833589fc
inflated $5,000                    SIGNED value=5000000000       to=ATTACKER chain-token=0x833589fc
whole balance 2^256-1              SIGNED value=1157920892373161 to=ATTACKER chain-token=0x833589fc
testnet base-sepolia               SIGNED value=10000            to=ATTACKER chain-token=0x036cbd53

 signature recovery : 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A == VICTIM (genuine, submittable transferWithAuthorization)
 validity window    : ~10 minutes — bearer instrument, whoever holds it can settle
```

The recovery line is the crux: `recoverTypedDataAddress` over the captured header returns the victim's address — the artifact is a **genuine, contract-submittable** authorization, not a malformed blob. Per §2.2 the practical loss ceiling is the victim's USDC balance on that chain; the $5,000 row is directly settleable against any wallet holding ≥ $5,000.

Also observed: **no default network restriction** — a `base-sepolia` challenge signs with equal willingness (prior-turn probe: `signEip3009Authorization` throws only for *unknown* networks; known testnets pass).

### 4.3 Normative anchor — ERC-8257 "Pricing Staleness and Payment Safety" (verbatim)

> *"Pricing lives in the manifest and is not committed anywhere that the endpoint is obligated to honor. … Agents that cached a manifest during discovery MUST re-fetch and re-verify the manifest (hash check, origin-binding, creator-binding) immediately before any payment-bearing invocation. A cached manifest MUST NOT be used as the basis for approving, signing, or submitting a payment transaction. Agents MUST be resilient to the endpoint returning a payment-required response whose amount differs from the cached manifest, and **MUST surface any price change to the user for explicit confirmation before proceeding**. Agents MUST NOT pre-approve payment amounts that assume the discovery-time manifest is authoritative beyond a short freshness window."*

The SDK is the layer where agent-framework integrators would discharge these MUSTs. It provides **no mechanism at all**: no manifest parameter, no `onPriceChange`/`confirm` callback, no comparison between challenge and any prior knowledge, and its own CLI violates the confirmation MUST outright (§7). The documented mitigations (`maxAmount` etc.) are static caps the *caller* must somehow know to set — the API never asks "does this challenge match what you were told?"

To be scrupulous about framing: the docstring means this is *documented behavior*, not a hidden backdoor. The finding is therefore precisely: **insecure-by-default design on a money-signing API + non-conformance with the standard's MUSTs + absence of any conformance affordance.** The vendor's own mitigation guidance stops at per-call opt-in caps and never mentions the registered manifest — the one artifact the whole ERC ecosystem treats as the price source of truth.

### 4.4 The bait-and-switch, end to end

1. Creator registers tool with manifest pricing `$0.01 → creator` (passes `validateManifest`; on-chain hash commits it; origin-binding + creator-binding all green).
2. Discovery surfaces (OpenSea tools page, agent frameworks) display $0.01 — *the only place the registered price exists.*
3. At invocation, the same endpoint returns a 402 for `$5,000 → attacker`. Nothing in the challenge must match any manifest field (amount, recipient, asset, network are all independent).
4. `paidFetch(url, {signer})` — the documented integration pattern for agents — signs it (§4.2).
5. Settlement moves the funds. Telemetry then reports the "successful" invocation (§5).

Every step uses published, documented API surface. No malformed manifest required — a **fully valid** manifest is simply ignored at the moment money moves. Part 1's Findings B/C make it worse (an *invalid* manifest — zero-address recipient, chain-mismatched pricing, 79-digit amounts — also sails through the validator that discovery layers are told to trust).

### 4.5 Remediation

1. **Make the safe path the only path for agents:** add a manifest-aware entry point, e.g. `paidFetch(url, { signer, manifest })`, that (a) verifies origin-binding/creator-binding/hash per the ERC, (b) rejects any challenge whose `{amount, payTo, asset, network}` doesn't match a `pricing[]` entry, (c) routes mismatches to a **mandatory confirmation callback** (`onPriceChange(challenge, manifestEntry) => Promise<boolean>`), defaulting to *reject*.
2. Default `maxAmount` to a non-∞ value (the CLI already picked $10 — make it a library default too) and default `allowedNetworks` to mainnets.
3. Deprecate the unbounded default in docs: "trusts the server" should be a red-flag warning at the top of the README payment section, with the manifest-bound API as the recommended pattern.

---

## 5. F3 — Usage telemetry launders server-controlled data to OpenSea's aggregator

### 5.1 The code

After a successful paid call, `paidFetch` (x402-payment.ts:278-295) extracts a settlement tx hash **from the responding server's headers** and reports it:

```ts
279:    const settlement = extractSettlementTxHash(paidRes)   // reads PAYMENT-RESPONSE / X-PAYMENT-RESPONSE
...
285:      reportCallerX402Usage(
286:        {
287:          toolEndpoint: url,          // the URL the CALLER passed — not necessarily who answered
288:          callerAddress: …,
289:          txHash: settlement,         // the server's claim, unverified
290:          chainId: resolved.chainId,
291:        }, …
```

`extractSettlementTxHash` (301-315) base64-decodes the header and returns `.transaction`. The reporter's validation (`caller-reporter.ts:240-245`) is **format only**:

```ts
if (!TX_HASH_REGEX.test(event.txHash)) → skipped   // /^0x[0-9a-fA-F]{64}$/ — nothing else
```

The POST that goes to `https://api.opensea.io/api/v2/tools/usage` (default; `caller-reporter.ts:275-292`):

```json
{ "verification_type": "x402_settlement",
  "tool_endpoint": "<caller-supplied URL>",
  "x402": { "caller_address": "…", "tx_hash": "<server-supplied>", "chain_id": 8453 } }
```

No client-side check that the tx **exists**, is a **USDC transfer**, went to **the challenge's `payTo`**, or moved **the challenge's amount**. API keys are auto-provisioned permissionlessly (`POST /api/v2/auth/keys`) when absent, so the pipe is open to any caller. The EIP-3009 reporter variant additionally ships the **raw signature, nonce and validity window** in the event (`CallerEip3009UsageEvent`, caller-reporter.ts:~90-110).

### 5.2 Demonstrated (probe S2 — local aggregator stand-in)

Combined with a probe-stage redirect (A → 302 → B; B challenges, receives payment, and answers with a **fabricated** settlement header):

```
=== S2: 302 on the PROBE — retarget + forged usage report ===
 payment actually went to : http://127.0.0.1:36659 (NOT the called origin http://127.0.0.1:33041)
 signed authorization     : to=0xdead000000000000000000000000000000000001 value=$0.01
 LOCAL AGGREGATOR (stands in for api.opensea.io) received:
   POST /api/v2/tools/usage
   body: {
     "verification_type": "x402_settlement",
     "tool_endpoint": "http://127.0.0.1:33041/tool",
     "x402": {
       "caller_address": "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
       "tx_hash": "0xabababababababababababababababababababababababababababababababab",
       "chain_id": 8453
     }
   }
```

Three integrity failures in one POST:

1. **`tx_hash` is fiction** — `0xabab…` is not a transaction at all; the pipeline's first line of truth came from the responding server's header. In a real attack the server returns any *real* Base tx hash — e.g. a 1-base-unit USDC self-transfer, or an unrelated historical tx — that plausibly survives a shallow existence check while corresponding to no actual payment for this invocation.
2. **Attribution confusion** — `tool_endpoint` names origin A (what the caller dialed); the payment and challenge came from origin B (where the redirect pointed). Usage credited to a tool that never served (or never was paid by) this invocation.
3. **Caller-address laundering** — the report binds the *victim caller's* address to the fabricated settlement, so downstream analytics/reputation see the honest caller as the payer of record.

### 5.3 Honest boundary

The server-side reporter docstring states the backend verifies settlement transactions, and `handleResponse` maps a 400 "already reported/duplicate" to `already-reported` — so the aggregator is not naive. **What cannot be assessed locally:** the depth of that backend verification (existence only? amount/recipient match against the challenge or manifest? dedup window?). The SDK-side, provable claim is: *the client transmits counterparty-controlled financial telemetry as ground truth, with format-only validation, and misattributes the endpoint under redirect.* Any backend trust placed in these fields is trust placed in the paying endpoint. Severity ceiling depends on what the aggregator does with usage data (rankings, revenue-share, rewards, billing reconciliation) — scope question for OpenSea (§11).

### 5.4 Remediation

- Verify before reporting: `eth_getTransactionReceipt(txHash)` on the reported chain; require `to == challenge.payTo`, USDC `Transfer(from == caller, value == challenge amount)` log, block confirmations ≥ N. The SDK already ships `viem` — this is a few lines.
- Report `responseUrl` (post-redirect final URL) alongside `toolEndpoint`, or refuse to report when they differ.
- Apply the same treatment to the EIP-3009 reporter; stop shipping raw signatures to the aggregator unless a settled-tx reference is unavailable (they are replay-window-bounded but still bearer artifacts).

---

## 6. F4 — The double-charge safety flag is decided by the party that profits from the lie

### 6.1 The code

`rejectServerErrorAfterPayment` (x402-payment.ts:53-68) throws on any 5xx after the signed request, and sets `X402PaymentError.settled` from **the presence of the server's own settlement headers**:

```ts
54:  if (res.status < 500) return
56:  const settlement = X402_SETTLEMENT_HEADERS.map(h => res.headers.get(h)).find(v => v != null)
59:  const settled = settlement != null
61:  throw new X402PaymentError(
62:    `x402: payment was signed and sent but the server returned ${res.status}` +
63:      (settled ? " — settlement headers present, payment may have been charged"
65:               : " — no settlement headers, payment was likely not settled"), …)
```

The design intent is right (never silently swallow a post-payment failure; never auto-retry — the SDK does **not** auto-retry, credit where due). But the signal's *content* is header-derived: the same server that holds the signed authorization decides whether the SDK tells the caller "likely not settled."

### 6.2 Demonstrated (probe S3)

Two runs, **identical on-chain reality** (server received a valid authorization and can settle it), opposite SDK conclusions:

```
=== S3: 502-after-signature — settled flag is header-derived ===
 server 502'd WITH settlement header = false -> X402PaymentError: settled=false
   SDK tells the caller: "x402: payment was signed and sent but the server returned 502 — no settlement headers, payment was likely not "
 server 502'd WITH settlement header = true  -> X402PaymentError: settled=true
   SDK tells the caller: "x402: payment was signed and sent but the server returned 502 — settlement headers present, payment may have b"
```

The double-charge recipe: malicious endpoint receives `X-PAYMENT` → settles on-chain → responds `502` **without** settlement headers → SDK reports `settled=false` ("likely not settled") → honest caller (or their retry logic, following the SDK's own guidance that no-settlement means probably-safe) re-invokes → signs a **fresh nonce** → endpoint settles again. The flag exists to prevent exactly this, and the adversary controls it.

### 6.3 Remediation

Ground `settled` in chain state, not headers: on 5xx, query USDC `Transfer` events / authorization-nonce usage for `from = payer` within the signature's window before populating the flag; report `settled: "unknown"` when the chain is unreachable. At minimum, reword the `false` branch to "settlement status unverifiable from response — check the chain before retrying," so the SDK stops asserting a fact its input cannot support.

---

## 7. F6 — The official CLI: display-then-sign, base-unit amounts, manifest-blind cap

`src/cli/commands/pay.ts` is OpenSea's own reference payment flow. Sequence (lines 341-366):

```ts
341:  console.log(pc.cyan("Payment requirements:"))
346:  console.log(`  Amount: ${requirements.maxAmountRequired}`)   // RAW BASE UNITS
347:  console.log(`  Pay To: ${requirements.payTo}`)
348:  console.log(`  Asset: ${requirements.asset}`)
350:  console.log(pc.cyan("\nSigning EIP-3009 transferWithAuthorization..."))
352:  const client = createX402Client(...)                          // ← signs IMMEDIATELY
```

- **Zero confirmation.** `grep -c "confirm\|prompt\|@clack" pay.ts` → `0`. The ERC MUST ("surface any price change … for explicit confirmation") has no implementation even in the interactive, human-present product — the one place it would be cheapest to honor.
- **Amount displayed as `10000000`**, not `$10.00` — base units of a 6-decimal token are noise to humans; a $5,000 demand prints as `5000000000` between two informational lines and is signed before the user can react.
- **The cap is a constant, not the manifest.** `DEFAULT_MAX_AMOUNT = "10000000"` (line 94) — $10 regardless of what the tool registered ($0.01 manifest → endpoint may demand $9.99 and the CLI signs silently; 999× the advertised price). `pay.ts` never reads a manifest (`grep -c manifest pay.ts` → 0).
- **`--max-amount unlimited`** (lines 192-195) disables the only guard, advertised in `--help` (line 109).

Remediation: fetch + hash-verify the registered manifest in `pay` (the CLI already contains the full hardened-fetch stack — F5!), derive the default cap from `pricing[].amount`, print `USDC`-formatted amounts and the manifest-vs-challenge delta, and require an explicit `confirm()` (dependency already shipped: `@clack/prompts`) before `createPaymentPayload`.

---

## 8. F5 — The hardening lives in the CLI; the money path ships naked

### 8.1 Bundle matrix (compiled `dist/`, v0.29.0)

| Bundle | `isPrivateHostname` | `classifyResolvedHostname` | `redirect:"manual"` | `AbortSignal.timeout` |
|---|---|---|---|---|
| `cli.js` | **4** | **3** | **7** | **10** |
| `index.js` (library entry) | 0 | 0 | 0 | 0 |
| all 6 `chunk-*.js` (incl. `chunk-MVH7MQCD.js` carrying `paidFetch`) | 0 | 0 | 0 | 0 |

Package-root exports: **91 symbols, none of them a network guard** (`isPrivateHostname` / `classifyResolvedHostname` are not exported at all — integrators cannot even reuse the SDK's own hardened resolution logic). Meanwhile `paidFetch`, `paidAuthenticatedFetch`, `eip3009AuthenticatedFetch`, `x402Gate`, `cdpX402Gate`, `payaiX402Gate`, the usage reporters and `createEip3009AuthHeader` are all root-exported for exactly the consumer class the ERC scopes its MUSTs to.

### 8.2 Normative anchor — ERC-8257 "Malicious Endpoints" (verbatim)

> *"Any consumer that may cause a tool to be invoked on a user's behalf (**agent frameworks**, wallets, invocation proxies, or any surface exposing a 'run this tool' affordance …) **MUST reject endpoints that resolve to private IP ranges** (RFC 1918, RFC 6598, loopback, link-local, IPv6 ULA `fc00::/7`, IPv6 link-local `fe80::/10`) to prevent Server-Side Request Forgery (SSRF) attacks against internal services, and **MUST resolve the host immediately before each invocation** rather than caching the resolution, to prevent DNS rebinding. … **Agent frameworks that invoke tool endpoints MUST enforce request timeouts and response size limits.**"*

`paidFetch` is the SDK's "invoke a tool endpoint on a user's behalf" surface — with money attached. It has none of the four MUST controls: it will POST to `http://169.254.169.254/…` or `http://127.0.0.1:8080/…` if an agent runtime passes such a URL (e.g., from a manifest whose `endpoint` was never re-checked — Part 1 showed `endpoint` is https-pinned in the *schema*, but a runtime that assembles URLs from other manifest fields, proxies, or user input has no SDK-side backstop), it follows redirects (F1), it imposes no timeout (a hanging tool hangs the agent's turn), and it caps no response size (an endpoint can stream unbounded bytes into the agent's context/memory). The CLI proves the authors can write all four controls — they exist, hardened, 4/3/7/10 occurrences strong — in the wrong binary.

**Nuance, stated honestly:** for `paidFetch` the *caller* chooses the URL, so classic SSRF (victim-server-forced fetch) mostly applies to agent runtimes that auto-invoke registry `endpoint`s — precisely the "agent frameworks" the ERC names. The redirect (F1), timeout and size-cap gaps apply to every caller unconditionally.

### 8.3 Remediation

Move the guard module into the library bundle; export `assertPublicHttpsTarget(url)`; apply it plus `AbortSignal.timeout` and a byte cap inside `paidFetch`/`paidAuthenticatedFetch` before both the probe and the paid replay; re-resolve and re-check at each stage (the CLI's `classifyResolvedHostname` post-DNS pattern, verbatim).

---

## 9. Linkage to Part 1 — the validator-trust chain, completed

| Part 1 finding | Part 2 consequence |
|---|---|
| **B**: `PricingEntrySchema` = four unconstrained strings; zero-address recipient, chain-mismatched asset/recipient, `-1`/`007`/79-digit amounts, uppercase hex all pass `validateManifest` | The blessed `pricing[0]` flows unvalidated into paywall construction: `dry-run-gate.ts:47-63` extracts `recipient` via a regex that **accepts uppercase hex** (`/:(0x[0-9a-fA-F]{40})$/`) and checks only `if (check.value)` non-emptiness — never agreement with anything else. A manifest the validator blessed can name a recipient the payer-side blocklist would reject on the wire (zero address): **the validator blesses what the signer refuses** — an internal contradiction between two layers of the same package. |
| **C**: parser-hardening ceilings missing/wrong (depth 32 vs ERC 16; no node/pricing/1 MiB caps) | Same consumer-hardening philosophy gap as F5: the ERC's MUST tables are implemented selectively, wherever the authors happened to be working (CLI, `access` block) — not wherever the standard scopes them (payment/invocation surfaces). |
| **A**: `image`/`featuredImage` accept `javascript:`/`file:`/`data:text/html` | Rendering-layer impact belongs to OpenSea's surfaces (out of local scope) — unchanged from Part 1 §4.5. |
| Part 1 negative result: `metadataURI` fetch fully hardened **in `cli.js`** | F5 shows the hardening never left the CLI. |

*(Self-correction carried forward from this investigation: an earlier working note claimed the `pay` CLI "reads a manifest and then moves money." It does not — `pay.ts` contains zero manifest references. The claim that **no payment path anywhere in the package reads a manifest** is the verified one, and it strengthens the finding.)*

---

## 10. What is NOT a finding (integrity record)

- **Facilitator module** (`middleware/x402-facilitators.ts`, 755 lines): hard timeouts on `/verify` + `/settle`, a reservation-based replay guard with explicit reasoning about stateless-verify concurrency, TTL'd nonce keys. Genuinely well-engineered.
- **`verifyXPaymentAuth`** (server-side identity): fails closed, pins domain/chainId/recipient, caps the replay window, recovers the signer. Hardened.
- **No auto-retry after payment failure** — `paidFetch` throws; it never re-signs on its own. (F4 is about the *content* of the thrown signal, not retry behavior.)
- **`paidAuthenticatedFetch` cumulative-cap logic** (lines 78-129): correct *when `maxAmount` is supplied* — one nonzero authorization per call, cumulative bound enforced. The gap is that supplying it is optional (F2).
- **`signEip3009Authorization` throws on unknown networks** — kills the earlier "fail-open on unrecognized network" hypothesis at the signer.
- **EIP-3009 protocol-level replay**: single-use nonce enforced by USDC ⇒ the ERC's replay-resistance MUST is met by protocol choice. F1 is a confidentiality failure, not a replay failure.
- **`toBaseUnits` round-trip through `dry-run-gate`**: idempotent for integer-string amounts (`"10000"` → `"10000"`) — the feared 10⁶ unit inflation does not occur; corrected mid-investigation by test.
- **`isSecureAggregatorUrl`**: correctly enforces https with a deliberate, documented loopback exception (which this report's probes use).
- **`X402PaymentError` existing at all** is good design; F4 asks only that its flag be grounded in truth.

---

## 11. Scope and submission guidance

**Provable from the published package alone (this report):** F1, F2, F4, F5, F6 and the SDK-side half of F3 — all demonstrated against compiled code with recoverable source citations.

**Requires OpenSea-authorized scope to close (do not test without it):**

1. Whether the aggregator (`api.opensea.io/api/v2/tools/usage`) verifies caller-reported `tx_hash` (existence? amount/recipient match? dedup?), and what consumes usage data (rankings, payouts, billing) — determines F3's ceiling.
2. Whether opensea.io rendering/agent-runtime surfaces consume validator-blessed invalid manifests (Part 1 A/B) and whether their payment flows use `paidFetch` defaults — determines the live blast radius of F2.
3. Whether any first-party OpenSea agent product calls `paidFetch`/`pay` without manifest-derived guards.

**Suggested report structure for submission:** lead with **F2** (ERC MUST conflict + demonstrated unbounded signing + the vendor docstring as an admission), attach **F1** as the escalation (the signed artifact is also extractable by third parties), **F5** as the systemic cause (hardening shipped in the wrong bundle), then F3/F4/F6. Keep Part 1's Findings B/C as the upstream validator story. Every claim here has a runnable probe; the ERC quotes are verbatim from the published draft (2026-04-17).

**Severity language discipline:** avoid "unlimited approval" phrasing — EIP-3009 is exact-value with insufficient-balance revert (§2.2). The accurate claim: *silent signing of arbitrary amounts up to the victim's balance, to arbitrary recipients, plus bearer-leakage of the signature to redirect targets.* Overclaiming the `2^256-1` row will cost credibility with a competent triager.

---

## 12. Reproduction

```bash
# 1. lab
mkdir -p /tmp/p2 && cd /tmp/p2
echo '{ "name":"p2","private":true,"type":"module","version":"1.0.0" }' > package.json
npm i @opensea/tool-sdk@0.29.0

# 2. probes (this part)
cp probes/07-critical-chain.mjs .
node 07-critical-chain.mjs        # ~3 s, prints S1–S5; archived output:
                                  # probes/07-critical-chain-output.txt

# 3. source recovery for line citations: probes/README.md
```

Static evidence commands:

```bash
# bundle guard matrix (F5)
cd node_modules/@opensea/tool-sdk/dist
for f in index.js cli.js chunk-*.js; do
  printf '%-24s priv=%s classify=%s manual=%s timeout=%s\n' "$f" \
    "$(grep -c isPrivateHostname $f)" "$(grep -c classifyResolvedHostname $f)" \
    "$(grep -c 'redirect: *"manual"' $f)" "$(grep -c AbortSignal.timeout $f)"
done

# no confirmation anywhere in the pay CLI (F6)
grep -c 'confirm\|prompt' <recovered>/src/cli/commands/pay.ts   # → 0

# no manifest anywhere in the payment path (F2)
grep -rn manifest <recovered>/src/lib/client/*.ts <recovered>/src/cli/commands/pay.ts   # → nothing
```

Probe output is deterministic modulo ephemeral ports and `validBefore` timestamps. Victim key is a throwaway; no probe contacts any remote host; no authorization is ever submitted to a chain.

*End of Part 2.*
