import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(new URL('../../hub-install/package.json', import.meta.url));
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const hubOrigin = 'https://hub.example';
const issuer = 'https://portal.example/api/idp';
const client = '8b438de5-6082-4d77-9a50-f41417fd4081';
const kid = '1afd3804-520d-46f0-aaee-838dd5380d6a';
const random = (length = 32) => randomBytes(length).toString('base64url');
const secret = random(48);
const upstreamBearer = client + '.' + random();
const subject = random();
const code = client + '.' + random();
const messageId = 'c'.repeat(64);
const attachment = new Uint8Array([0, 33, 255]);
const cursor = random();
const hash = value => createHash('sha256').update(value).digest('base64url');
const part = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const endpoint = path => issuer + path;
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };

let authorization;
let authorizationSubject;
let sourceRevoked = false;
let mailProviderError = false;
let redirectedMail = false;
let foreignRequests = 0;
let wrongMailboxIdentity = false;
let jwtFailure;
let exchangeCount = 0;
let folderCursorCount = 0;
const metadata = {
  id: messageId, from: 'sender@example.test', to: 'inbox@example.test', subject: 'Synthetic receipt',
  receivedAt: '2024-10-01T21:11:05.000Z', read: false, folder: 'inbox', attachmentCount: 1, size: 3,
};

async function portal(request) {
  const url = new URL(request.url);
  if (url.origin !== new URL(issuer).origin) {
    foreignRequests++;
    return Response.json({ error: 'wrong_origin' }, { status: 400 });
  }
  const suffix = url.pathname.slice('/api/idp'.length);
  const auth = request.headers.get('authorization');
  if (request.method === 'GET' && suffix === '/.well-known/openid-configuration') {
    assert.equal(auth, null);
    return Response.json({
      issuer, authorization_endpoint: endpoint('/authorize'), token_endpoint: endpoint('/token'),
      userinfo_endpoint: endpoint('/userinfo'), jwks_uri: endpoint('/jwks'), grant_types_supported: ['authorization_code'],
      response_types_supported: ['code'], token_endpoint_auth_methods_supported: ['client_secret_basic'],
      id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'],
      scopes_supported: ['openid', 'email', 'mail.read'], authorization_response_iss_parameter_supported: true,
    });
  }
  if (request.method === 'POST' && suffix === '/token') {
    exchangeCount++;
    assert.equal(auth, 'Basic ' + Buffer.from(client + ':' + secret).toString('base64'));
    const form = new URLSearchParams(await request.text());
    assert.equal(form.get('grant_type'), 'authorization_code');
    assert.equal(form.get('code'), code);
    assert.equal(form.get('redirect_uri'), hubOrigin + '/v1/auth/portal/callback');
    assert.equal(hash(form.get('code_verifier')), authorization.searchParams.get('code_challenge'));
    const now = Math.floor(Date.now() / 1000);
    const header = part({ alg: 'RS256', typ: 'JWT', kid });
    const claims = part({ iss: issuer, aud: client, sub: authorizationSubject ?? subject,
      nonce: jwtFailure === 'nonce' ? random() : authorization.searchParams.get('nonce'), iat: now, exp: now + 300 });
    const input = [header, claims].join('.');
    const signature = sign('RSA-SHA256', Buffer.from(input), privateKey);
    if (jwtFailure === 'signature') signature[0] ^= 1;
    return Response.json({ token_type: 'Bearer', access_token: upstreamBearer, expires_in: 300,
      scope: authorization.searchParams.get('scope'), id_token: input + '.' + signature.toString('base64url') });
  }
  if (request.method === 'GET' && suffix === '/jwks') {
    assert.equal(auth, null);
    return Response.json({ keys: [jwk] });
  }
  assert.equal(request.method, 'GET');
  assert.equal(auth, 'Bearer ' + upstreamBearer);
  if (sourceRevoked) return Response.json({ error: 'invalid_token' }, { status: 401 });
  if (suffix === '/userinfo') return Response.json({ sub: authorizationSubject ?? subject, email: 'account@example.test' });
  if (mailProviderError) return Response.json({ error: 'mail_provider_unavailable' }, { status: 503 });
  if (suffix === '/mail') {
    if (redirectedMail) return Response.redirect('https://foreign.example/redirected', 307);
    const folder = url.searchParams.get('folder');
    assert.equal(url.searchParams.get('limit'), '20');
    if (url.searchParams.has('cursor')) {
      assert.equal(url.searchParams.get('cursor'), cursor);
      folderCursorCount++;
      return Response.json({ sub: subject, messages: [] });
    }
    const messages = folder === 'inbox' ? [metadata] : [];
    return Response.json({ sub: wrongMailboxIdentity ? random() : subject, messages, ...(messages.length ? { cursor } : {}) });
  }
  if (suffix === '/mail/' + messageId) return Response.json({ sub: subject, message: {
    ...metadata, text: '', html: '<p>Receipt &amp; data</p><script>hidden()</script>',
    attachments: [{ id: '0', filename: 'receipt.bin', mime: 'application/octet-stream', size: 3 }],
  } });
  if (suffix === '/mail/' + messageId + '/attachments/0') return new Response(attachment, { headers: {
    'Content-Type': 'application/octet-stream', 'Content-Length': '3',
    'Content-Disposition': "attachment; filename=\"attachment\"; filename*=UTF-8''receipt.bin",
  } });
  return Response.json({ error: 'mail_not_found' }, { status: 404 });
}

const config = new Miniflare(convertV4MiniflareOptions({ logRequests: false, enableDevRegistry: false, workers: [
  {
    name: 'pages', modules: true, serviceBindings: { HUB: 'hub' }, compatibilityDate: '2026-11-25',
    script: 'export default { fetch(request, env) { return env.HUB.fetch(request); } };',
  },
  {
    name: 'hub',
    modulesRoot: fileURLToPath(new URL('../build/', import.meta.url)),
    modules: [
      { type: 'ESModule', path: fileURLToPath(new URL('../build/index.js', import.meta.url)), contents: await readFile(new URL('../build/index.js', import.meta.url), 'utf8') },
      { type: 'CompiledWasm', path: fileURLToPath(new URL('../build/index_bg.wasm', import.meta.url)), contents: await readFile(new URL('../build/index_bg.wasm', import.meta.url)) },
    ],
    compatibilityDate: '2026-11-25', compatibilityFlags: ['request_signal_passthrough'],
    bindings: { HUB_ORIGIN: hubOrigin, PORTAL_ISSUER: issuer, PORTAL_CLIENT_ID: client,
      PORTAL_CLIENT_SECRET: secret, HUB_ENCRYPTION_KEY: random() },
    d1Databases: { DB: 'hub-test-d1' }, outboundService: portal,
  },
] }));

const api = (path, request = {}) => config.dispatchFetch(hubOrigin + path, { redirect: 'manual', ...request });
const body = value => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
const bearer = token => ({ headers: { Authorization: 'Bearer ' + token } });

async function expectStatus(response, status) {
  const actual = await response;
  if (actual.status !== status) {
    assert.fail('Expected HTTP ' + status + ', got ' + actual.status + ' ' + (await actual.text()).slice(0, 64));
  }
  return actual;
}

async function create(mailRead, proof = random(), { durable, token } = {}) {
  const request = body({ proofChallenge: hash(proof), mailRead, ...(durable ? { durable } : {}) });
  if (token) request.headers.Authorization = 'Bearer ' + token;
  const response = await expectStatus(api('/v1/auth/portal/transactions', request), 201);
  const transaction = await response.json();
  authorization = new URL(transaction.authorizationUrl);
  assert.equal(authorization.origin, new URL(issuer).origin);
  assert.equal(authorization.pathname, '/api/idp/authorize');
  assert.equal(authorization.searchParams.get('scope'), mailRead ? 'openid email mail.read' : 'openid email');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(transaction.expiresIn > 0 && transaction.expiresIn <= 300);
  const path = '/v1/auth/portal/transactions/' + transaction.transactionId;
  return { proof, path, state: authorization.searchParams.get('state') };
}

const callback = (tx, results = { code }) => api('/v1/auth/portal/callback?' + new URLSearchParams({ state: tx.state, iss: issuer, ...results }));
const complete = tx => api(tx.path + '/complete', body({ proof: tx.proof }));
const cancel = tx => api(tx.path + '/cancel', body({ proof: tx.proof }));

try {
  const d1 = await config.getD1Database('DB', 'hub');
  for (const migration of ['0001_identity.sql', '0002_durable_identity_and_vault.sql', '0003_secure_notes.sql']) {
    const sql = await readFile(new URL('../migrations/' + migration, import.meta.url), 'utf8');
    for (const statement of sql.split(';').map(s => s.trim()).filter(Boolean)) {
      await d1.prepare(statement).run();
    }
  }
  const discovery = await expectStatus(api('/.well-known/loft-app'), 200);
  assert.equal(discovery.headers.get('Cache-Control'), 'private, no-store');
  const descriptor = await discovery.json();
  assert.equal(descriptor.issuer, issuer);
  assert.deepEqual(descriptor.modules, ['mail']);
  const supported = await expectStatus(api('/.well-known/loft-app', { headers: { 'X-Loft-Capabilities': 'notes-sync/1' } }), 200);
  assert.deepEqual((await supported.json()).modules, ['mail', 'notes_sync']);

  const tx = await create(true);
  const pending = await expectStatus(complete(tx), 202);
  assert.deepEqual(await pending.json(), { status: 'pending' });
  await expectStatus(complete({ ...tx, proof: random() }), 410);
  const callbackResult = await expectStatus(callback(tx), 303);
  assert.equal(callbackResult.headers.get('location'), hubOrigin + '/v1/auth/portal/return');
  const returned = await expectStatus(api('/v1/auth/portal/return', { headers: { 'Accept-Language': 'ja,en;q=0.7' } }), 200);
  assert.ok((await returned.text()).includes('LOFT に戻る'));
  await expectStatus(callback(tx), 410);
  const repeated = await Promise.all([complete(tx), complete(tx)]);
  const [session, recovery] = await Promise.all(repeated.map(async response => (await expectStatus(response, 200)).json()));
  assert.equal(session.sessionToken, recovery.sessionToken);
  assert.equal(session.subject, subject);
  assert.equal(session.mailRead, true);
  assert.ok(session.expiresIn > 0 && session.expiresIn <= 300);
  assert.equal(exchangeCount, 1);
  assert.ok(!JSON.stringify(session).includes(upstreamBearer));
  const databaseRow = await d1.prepare('SELECT * FROM hub_login WHERE phase = ?').bind('issued').first();
  assert.equal(databaseRow.auth_box, null);
  assert.ok(!JSON.stringify(databaseRow).includes(upstreamBearer));
  assert.ok(!JSON.stringify(databaseRow).includes(session.sessionToken));
  assert.ok(!JSON.stringify(databaseRow).includes(tx.proof));
  const auth = bearer(session.sessionToken);
  await expectStatus(api('/v1/session', auth), 200);
  assert.equal((await (await expectStatus(api('/v1/mail/messages?folder=inbox', auth), 200)).json()).messages[0].read, false);
  await expectStatus(api('/v1/mail/messages?folder=inbox&cursor=' + cursor, auth), 200);
  assert.equal(folderCursorCount, 1);
  await expectStatus(api('/v1/mail/messages?folder=trash', auth), 200);
  await expectStatus(api('/v1/mail/messages?account=anyone', auth), 400);
  const message = await (await expectStatus(api('/v1/mail/messages/' + messageId, auth), 200)).json();
  assert.ok(message.message.text.includes('Receipt & data'));
  assert.ok(!message.message.text.includes('hidden()'));
  assert.equal(message.message.read, false);
  assert.equal(message.message.html, undefined);
  const content = await expectStatus(api('/v1/mail/messages/' + messageId + '/content', auth), 200);
  assert.ok((await content.text()).includes('Receipt & data'));
  const download = await expectStatus(api('/v1/mail/messages/' + messageId + '/attachments/0', auth), 200);
  assert.equal(download.headers.get('Content-Type'), 'application/octet-stream');
  assert.equal(download.headers.get('Content-Length'), '3');
  assert.deepEqual(new Uint8Array(await download.arrayBuffer()), attachment);
  await expectStatus(api('/v1/mail/messages/' + 'd'.repeat(64), auth), 404);
  redirectedMail = true;
  await expectStatus(api('/v1/mail/messages', auth), 503);
  assert.equal(foreignRequests, 0);
  redirectedMail = false;
  wrongMailboxIdentity = true;
  await expectStatus(api('/v1/mail/messages', auth), 503);
  wrongMailboxIdentity = false;
  mailProviderError = true;
  await expectStatus(api('/v1/mail/messages', auth), 503);
  mailProviderError = false;
  sourceRevoked = true;
  await expectStatus(complete(tx), 401);
  await expectStatus(api('/v1/mail/messages', auth), 401);
  sourceRevoked = false;
  await expectStatus(api('/v1/logout', { ...auth, method: 'POST' }), 204);
  await expectStatus(api('/v1/session', auth), 401);
  await expectStatus(complete(tx), 410);

  const identity = await create(false);
  await expectStatus(callback(identity), 303);
  const identitySession = await (await expectStatus(complete(identity), 200)).json();
  await expectStatus(api('/v1/mail/messages', bearer(identitySession.sessionToken)), 403);
  await expectStatus(cancel(identity), 204);
  await expectStatus(api('/v1/session', bearer(identitySession.sessionToken)), 401);

  const declined = await create(true);
  await expectStatus(callback(declined, { error: 'access_denied' }), 303);
  await expectStatus(complete(declined), 403);
  const cancelled = await create(true);
  await expectStatus(cancel(cancelled), 204);
  await expectStatus(callback(cancelled), 410);

  for (const invalid of ['nonce', 'signature']) {
    jwtFailure = invalid;
    const invalidTx = await create(true);
    await expectStatus(callback(invalidTx), 303);
    await expectStatus(complete(invalidTx), 403);
  }
  jwtFailure = undefined;
  const enrolled = await create(true, random(), { durable: true });
  await expectStatus(callback(enrolled), 303);
  const [device, repeatedEnrollment] = await Promise.all([complete(enrolled), complete(enrolled)])
    .then(responses => Promise.all(responses.map(async response => (await expectStatus(response, 200)).json())));
  assert.equal(device.sessionToken, repeatedEnrollment.sessionToken);
  assert.equal(device.durable, true);
  const authDevice = bearer(device.sessionToken);
  const durableRows = await d1.prepare('SELECT session_hash, identity_box, mail_box FROM hub_device_session').all();
  assert.equal(durableRows.results.length, 1);
  assert.ok(!JSON.stringify(durableRows).includes(device.sessionToken));
  assert.ok(!JSON.stringify(durableRows).includes(upstreamBearer));

  const vaultPath = '/v1/vault/' + random();
  const ciphertext = random(64);
  const put = (token, baseRevision, value, path = vaultPath) => {
    const request = body({ baseRevision, ciphertext: value });
    request.headers.Authorization = 'Bearer ' + token;
    return api(path, { ...request, method: 'PUT' });
  };
  await expectStatus(api(vaultPath, authDevice), 404);
  await expectStatus(api(vaultPath, auth), 401);
  const cas = await Promise.all([put(device.sessionToken, 0, ciphertext), put(device.sessionToken, 0, random(64))]);
  assert.deepEqual(cas.map(value => value.status).sort(), [200, 409]);
  const vault = await (await expectStatus(api(vaultPath, authDevice), 200)).json();
  assert.equal(vault.revision, 1);
  assert.deepEqual(await (await expectStatus(put(device.sessionToken, 1, ciphertext), 200)).json(), { revision: 2 });
  await expectStatus(put(device.sessionToken, 2, random(256 * 1024 + 1)), 413);

  const notesPath = '/v1/notes';
  const notesCiphertext = random(72);
  const notesIfCurrent = { headers: { ...authDevice.headers, 'If-None-Match': '"1"' } };
  await expectStatus(api(notesPath, auth), 401);
  await expectStatus(api(notesPath, authDevice), 404);
  await expectStatus(put(device.sessionToken, 0, random(256 * 1024 + 1), notesPath), 413);
  assert.deepEqual(await (await expectStatus(put(device.sessionToken, 0, notesCiphertext, notesPath), 200)).json(), { revision: 1 });
  await expectStatus(put(device.sessionToken, 0, random(72), notesPath), 409);
  const notesRead = await expectStatus(api(notesPath, authDevice), 200);
  assert.equal(notesRead.headers.get('ETag'), '"1"');
  assert.deepEqual(await notesRead.json(), { revision: 1, ciphertext: notesCiphertext });
  const notesUnchanged = await expectStatus(api(notesPath, notesIfCurrent), 304);
  assert.equal(notesUnchanged.headers.get('ETag'), '"1"');
  assert.equal(notesUnchanged.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(await notesUnchanged.text(), '');
  for (const invalid of ['W/"1"', '*', '"01"', '"0"', '"4294967296"', '"1", "2"']) {
    await expectStatus(api(notesPath, { headers: { ...authDevice.headers, 'If-None-Match': invalid } }), 400);
  }
  const peerEnrollment = await create(false, random(), { durable: true });
  await expectStatus(callback(peerEnrollment), 303);
  const peer = await (await expectStatus(complete(peerEnrollment), 200)).json();
  assert.deepEqual(await (await expectStatus(api(notesPath, bearer(peer.sessionToken)), 200)).json(), { revision: 1, ciphertext: notesCiphertext });

  const revoked = await (await expectStatus(api('/v1/session', authDevice), 200)).json();
  assert.equal(revoked.durable, true);
  await d1.prepare('UPDATE hub_device_session SET mail_expires_at = 1 WHERE mail_box IS NOT NULL').run();
  const expiredGrant = await (await expectStatus(api('/v1/session', authDevice), 200)).json();
  assert.equal(expiredGrant.mailRead, false);
  assert.equal(expiredGrant.expiresIn, 0);
  const consentRequired = await expectStatus(api('/v1/mail/messages', authDevice), 403);
  assert.deepEqual(await consentRequired.json(), { error: 'mail_consent_required' });
  await expectStatus(api(vaultPath, authDevice), 200);

  const renewed = await create(true, random(), { durable: true, token: device.sessionToken });
  await expectStatus(callback(renewed), 303);
  const sameDevice = await (await expectStatus(complete(renewed), 200)).json();
  assert.equal(sameDevice.sessionToken, device.sessionToken);
  await expectStatus(api('/v1/mail/messages', authDevice), 200);

  authorizationSubject = random();
  const wrongAccount = await create(true, random(), { durable: true, token: device.sessionToken });
  await expectStatus(callback(wrongAccount), 303);
  await expectStatus(complete(wrongAccount), 403);
  const otherEnrollment = await create(true, random(), { durable: true });
  await expectStatus(callback(otherEnrollment), 303);
  const otherDevice = await (await expectStatus(complete(otherEnrollment), 200)).json();
  await expectStatus(api(notesPath, { headers: { ...bearer(otherDevice.sessionToken).headers, 'If-None-Match': '"1"' } }), 404);
  await expectStatus(put(otherDevice.sessionToken, 1, random(72), notesPath), 409);
  await expectStatus(api(vaultPath, bearer(otherDevice.sessionToken)), 404);
  await expectStatus(put(otherDevice.sessionToken, 2, random(64)), 409);
  const sharedPath = '/v1/vault/' + random();
  const deviceClock = performance.now();
  const waveSize = 32;
  const sameOwner = await Promise.all(Array.from({ length: waveSize }, () =>
    put(device.sessionToken, 0, random(64), sharedPath)));
  const sameOwnerCodes = sameOwner.map(response => response.status);
  assert.equal(sameOwnerCodes.filter(code => code === 200).length, 1);
  assert.ok(sameOwnerCodes.every(code => [200, 409, 429].includes(code)));
  const shared = await (await expectStatus(api(sharedPath, authDevice), 200)).json();
  assert.equal(shared.revision, 1);
  await expectStatus(api(sharedPath, bearer(otherDevice.sessionToken)), 404);

  const siblingPaths = Array.from({ length: 4 }, () => '/v1/vault/' + random());
  const independent = await Promise.all(siblingPaths.flatMap(path =>
    [device.sessionToken, otherDevice.sessionToken].map(token => put(token, 0, random(64), path))));
  assert.ok(independent.every(response => [200, 429].includes(response.status)));
  for (const [index, path] of siblingPaths.entries()) {
    for (const [owner, token] of [device.sessionToken, otherDevice.sessionToken].entries()) {
      if (independent[index * 2 + owner].status === 429) {
        await expectStatus(put(token, 0, random(64), path), 200);
      }
    }
    const [a, b] = await Promise.all([authDevice, bearer(otherDevice.sessionToken)].map(async credentials =>
      (await expectStatus(api(path, credentials), 200)).json()));
    assert.equal(a.revision, 1);
    assert.equal(b.revision, 1);
    assert.notEqual(a.ciphertext, b.ciphertext);
  }
  const elapsed = Math.round(performance.now() - deviceClock);
  console.log('workerd CAS wave: ' + waveSize + ' same-target requests, '
    + [200, 409, 429].map(code => code + '=' + sameOwnerCodes.filter(result => result === code).length).join(' ')
    + ', 8 cross-account writes, ' + elapsed + ' ms local fixture');
  authorizationSubject = undefined;

  const logoutRace = await create(true, random(), { durable: true, token: device.sessionToken });
  await expectStatus(callback(logoutRace), 303);
  await expectStatus(api('/v1/logout', { ...authDevice, method: 'POST' }), 204);
  await expectStatus(complete(logoutRace), 410);
  await expectStatus(api('/v1/session', authDevice), 401);
  await expectStatus(api(vaultPath, authDevice), 401);
  await expectStatus(api(notesPath, notesIfCurrent), 401);
  await expectStatus(api('/v1/auth/portal/transactions', {
    ...body({ proofChallenge: hash(random()), mailRead: true, durable: true }),
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + device.sessionToken },
  }), 401);

  const reenroll = await create(false, random(), { durable: true });
  await expectStatus(callback(reenroll), 303);
  const recovered = await (await expectStatus(complete(reenroll), 200)).json();
  const vaultAfterLogout = await (await expectStatus(api(vaultPath, bearer(recovered.sessionToken)), 200)).json();
  assert.deepEqual(vaultAfterLogout, { revision: 2, ciphertext });
  assert.deepEqual(await (await expectStatus(api(notesPath, bearer(recovered.sessionToken)), 200)).json(), { revision: 1, ciphertext: notesCiphertext });

  const discardedEnrollment = await create(false, random(), { durable: true });
  await expectStatus(callback(discardedEnrollment), 303);
  const discarded = await (await expectStatus(complete(discardedEnrollment), 200)).json();
  await expectStatus(cancel(discardedEnrollment), 204);
  await expectStatus(api('/v1/session', bearer(discarded.sessionToken)), 401);

  console.log('PASS: workerd Pages binding, legacy and durable D1 identity, own-mail authority, encrypted vault and notes CAS, 304 empty body');
} finally {
  await config.dispose();
}
