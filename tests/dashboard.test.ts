import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { chromium } from '@playwright/test';
import { Server, createMcpHandler } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

test('owner dashboard keeps untrusted metadata out of HTML sinks and secrets out of storage', async () => {
  const script = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(script, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/);
  assert.doesNotMatch(script, /localStorage\.setItem\([^\n]*(?:token|secret|password)/);
  assert.match(script, /x-csrf-token/);
  assert.match(script, /credentials: 'same-origin'/);
  assert.match(script, /\/auth\/session/);
});

test('browser uses the actual app for claim, policy edits, credentials, client issue, backup and logout', {timeout: 120000}, async () => {
  const { Hub } = await import('../src/core.js');
  const { loadConfig } = await import('../src/config.js');
  const { createApp } = await import('../src/app.js');
  const dir = await mkdtemp(join(tmpdir(), 'wheremymcp-dashboard-'));
  const reservation = createServer();
  await new Promise<void>(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const reserved = reservation.address(); assert(reserved && typeof reserved !== 'string');
  const port = reserved.port;
  await new Promise<void>(resolve => reservation.close(() => resolve()));
  const config = loadConfig({HUB_DATA_DIR: dir, HUB_PORT: String(port)});
  const key = randomBytes(32);
  await writeFile(config.masterKeyFile, key, {mode: 0o600});
  await writeFile(config.bootstrapTokenFile, 'local-browser-claim', {mode: 0o600});
  const hub = new Hub(join(dir, 'hub.sqlite'), key, config);
  const app = await createApp(hub);
  let scaleManifest:any[]|undefined;
  const upstreamHandler = createMcpHandler(() => {
    const server = new Server({name: 'browser-fixture', version: '1'}, {capabilities: {tools: {}}});
    server.setRequestHandler('tools/list', () => ({tools: scaleManifest || [{name: 'append', description: 'Append a reviewed note', inputSchema: {type: 'object', properties: {text: {type: 'string'}}, required: ['text'], additionalProperties: false}}]}));
    server.setRequestHandler('tools/call', request => ({content: [{type: 'text', text: String(request.params.arguments?.text)}]}));
    return server;
  });
  const upstreamNodeHandler = toNodeHandler(upstreamHandler);
  const upstreamServer = createServer((request, response) => {
    if (request.headers.authorization !== 'Bearer credential-canary-browser') { response.writeHead(401); response.end(); return; }
    void upstreamNodeHandler(request, response);
  });
  await new Promise<void>(resolve => upstreamServer.listen(0, '127.0.0.1', resolve));
  const upstreamAddress = upstreamServer.address(); assert(upstreamAddress && typeof upstreamAddress !== 'string');
  const sdkClients: Client[] = [];
  let browser;
  try {
    await app.listen({host: '127.0.0.1', port});
    browser = await chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 1280, height: 900}});
    page.setDefaultTimeout(7000);
    const errors: string[] = [];

        page.on('pageerror', error => errors.push(error.message));
    async function view(name: string) { await page.goto(`${config.origin}/#${name}`); await page.locator('main[aria-busy="false"]').waitFor(); }
    await page.goto(config.origin);
    await page.getByLabel('Setup token').fill('local-browser-claim');
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Create owner account'}).click();
    await page.getByRole('heading', {name: 'Save your recovery codes'}).waitFor();
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM recovery_code').get() as any).n, 10);
    await page.getByRole('button', {name: 'I saved it'}).click();
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.getByRole('heading', {name: 'Gateway policy is active'}).waitFor();
    await page.reload();
    await page.getByRole('heading', {name: 'Gateway policy is active'}).waitFor();
    await view('connections');
    await page.getByRole('button', {name: 'Add connection'}).click();
    await page.getByLabel('Account alias').fill('browser-private-account');
    await page.getByLabel('Token / API key / OAuth client secret').fill('credential-canary-browser');
    await page.getByRole('button', {name: 'Create connection'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('heading', {name: 'browser-private-account'}).waitFor();
    const connection = hub.db.prepare('SELECT id,credential FROM connection WHERE alias=?').get('browser-private-account') as any;
    assert(!connection.credential.includes('credential-canary-browser'));
    assert(!(await page.locator('main').innerText()).includes('credential-canary-browser'));
    await page.getByRole('button', {name: 'Edit connection'}).click();
    await page.getByLabel('Account identity').fill('browser-owner@example.test');
    await page.getByRole('button', {name: 'Save connection'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT identity FROM connection WHERE id=?').get(connection.id) as any).identity, 'browser-owner@example.test');
    await view('upstreams');
    await page.getByRole('button', {name: 'Register server', exact: true}).click();
    await page.getByLabel('Server name').fill('Local review server');
    await page.getByLabel('Remote MCP URL').fill(`http://127.0.0.1:${upstreamAddress.port}/mcp`);
    await page.getByLabel('Account connection').selectOption(connection.id);
    await page.getByLabel('Explicit local IP allowlist').fill('["127.0.0.1"]');
    await page.getByRole('dialog').getByRole('button', {name: 'Register server'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    const upstream = hub.db.prepare('SELECT id FROM upstream WHERE name=?').get('Local review server') as any;
    assert(upstream?.id);
    assert.equal(await page.getByRole('button', {name: 'Disable', exact: true}).isDisabled(), true, 'Pending servers cannot be disabled');
    await page.getByRole('button', {name: 'Edit server'}).click();
    await page.getByLabel('Request timeout').fill('20000');
    await page.getByRole('button', {name: 'Save server'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT timeout_ms FROM upstream WHERE id=?').get(upstream.id) as any).timeout_ms, 20000);
    await page.getByRole('button', {name: 'Refresh tools', exact: true}).click();
    await page.getByText('Discovery refreshed. Auto approve trusted tools or review them individually.', {exact: true}).waitFor();
    await page.getByRole('button', {name: 'Approve server', exact: true}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Approve server'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal(await page.getByRole('button', {name: 'Approve server', exact: true}).isDisabled(), true, 'Active servers cannot be approved again');
    await page.getByRole('button', {name: 'Disable', exact: true}).click();
    await page.getByRole('button', {name: 'Disable server', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal(await page.getByRole('button', {name: 'Disable', exact: true}).isDisabled(), true, 'Disabled servers cannot be disabled again');
    await page.getByRole('button', {name: 'Approve server', exact: true}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Approve server'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    const discovered = hub.db.prepare('SELECT id,name,gateway_name FROM tool WHERE upstream_id=?').get(upstream.id) as any;
    assert(discovered?.id, 'Refresh discovers a tool from the real MCP HTTP fixture');
    const toolId = discovered.id;
    await view('tools');
    await page.getByRole('button', {name: 'Review tool'}).click();
    assert.equal(await page.getByLabel('Tool behavior').evaluate((input: HTMLSelectElement) => input.required && input.validity.valueMissing), true, 'New tools require an explicit risk choice before submission');
    await page.getByLabel('Tool behavior').selectOption('write');
    await page.getByRole('button', {name: 'Enable tool'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT enabled FROM tool WHERE id=?').get(toolId) as any).enabled, 1);
    await view('profiles');
    await page.getByRole('button', {name: 'Edit tool access'}).first().click();
    await page.getByRole('checkbox', {name: `Allow ${discovered.name}`, exact: true}).check();
    await page.getByRole('button', {name: 'Save access'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT connection_id FROM profile_grant WHERE tool_id=?').get(toolId) as any).connection_id, connection.id);
    await page.getByRole('button', {name: 'Clone', exact: true}).first().click();
    await page.getByLabel('New profile name').fill('Browser cloned policy');
    await page.getByRole('button', {name: 'Clone with grants'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM profile_grant').get() as any).n, 2);
    await page.getByRole('button', {name: 'Create profile', exact: true}).click();
    await page.getByLabel('Profile name').fill('Browser custom policy');
    await page.getByRole('dialog').getByRole('button', {name: 'Create profile', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert(hub.db.prepare('SELECT id FROM profile WHERE name=?').get('Browser custom policy'));
    await view('clients');
    await page.getByRole('button', {name: 'Issue client token'}).click();
    await page.getByLabel('Client name').fill('Browser scoped client');
    await page.getByRole('button', {name: 'Issue token', exact: true}).click();
    await page.getByRole('heading', {name: 'Save client token'}).waitFor();
    const issuedToken = await page.getByRole('dialog').locator('pre').first().innerText();
    assert.match(issuedToken, /^umcp_/);
    await page.getByRole('button', {name: 'I saved it'}).click();
    const client = hub.db.prepare('SELECT id FROM client WHERE name=?').get('Browser scoped client') as any;
    const sdk = new Client({name: 'browser-policy-e2e', version: '1'}); sdkClients.push(sdk);
    await sdk.connect(new StreamableHTTPClientTransport(new URL(`${config.origin}/mcp`), {requestInit: {headers: {authorization: `Bearer ${issuedToken}`}}}));
    assert.equal((await sdk.listTools()).tools.length, 1);
    await assert.rejects(sdk.callTool({name: discovered.gateway_name, arguments: {text: 'reviewed content'}}));
    await view('overview');
    assert.equal(await page.locator('main').evaluate(main => [...main.childNodes].some(node => node.nodeType === Node.TEXT_NODE && node.textContent?.trim() === 'null')), false, 'Completed onboarding must not render a literal null');
    await view('approvals');
    await page.locator('#field-client_id').selectOption(client.id);
    await page.getByLabel('Write or delete tool').selectOption(toolId);
    await page.getByLabel('Exact argument object').fill('{"text":"reviewed content"}');
    await page.getByRole('button', {name: 'Approve one call'}).click();
    await page.getByRole('heading', {name: 'One-use call approval'}).waitFor();
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM approval').get() as any).n, 1);
    const approvalId = await page.getByRole('dialog').locator('pre').first().innerText();
    assert.match(JSON.stringify(await sdk.callTool({name: discovered.gateway_name, arguments: {text: 'reviewed content'}, _meta: {wheremymcp_approval_id: approvalId}})), /reviewed content/);
    await assert.rejects(sdk.callTool({name: discovered.gateway_name, arguments: {text: 'reviewed content'}, _meta: {wheremymcp_approval_id: approvalId}}));
    await page.getByRole('dialog').getByRole('button', {name: 'Close', exact: true}).click();
    await view('clients');
    await page.getByRole('button', {name: 'Client config', exact: true}).click();
    for (const kind of ['codex', 'claude', 'cursor', 'gemini', 'hermes', 'other']) {
      if (kind !== 'codex') {
        await page.getByRole('dialog').getByRole('button', {name: 'Close', exact: true}).click();
        await page.getByRole('button', {name: 'Client config', exact: true}).click();
      }
      await page.getByLabel('Config format').selectOption(kind);
      await page.getByRole('button', {name: 'Generate config', exact: true}).click();
      await page.getByRole('heading', {name: 'Client configuration'}).waitFor();
      const snippet = await page.getByRole('dialog').locator('pre').innerText();
      assert(snippet.includes('WHEREMYMCP_TOKEN') && !snippet.includes(issuedToken), `${kind} config must reference an environment variable`);
    }
    await page.getByRole('dialog').getByRole('button', {name: 'Close', exact: true}).click();
    await page.getByRole('button', {name: 'Rotate token', exact: true}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Rotate token', exact: true}).click();
    await page.getByRole('heading', {name: 'Save replacement token'}).waitFor();
    const replacementToken = await page.getByRole('dialog').locator('pre').first().innerText();
    assert.notEqual(replacementToken, issuedToken);
    await assert.rejects(sdk.listTools(), 'Rotation immediately rejects the previous token');
    const rotatedSdk = new Client({name: 'browser-policy-rotated', version: '1'}); sdkClients.push(rotatedSdk);
    await rotatedSdk.connect(new StreamableHTTPClientTransport(new URL(`${config.origin}/mcp`), {requestInit: {headers: {authorization: `Bearer ${replacementToken}`}}}));
    assert.equal((await rotatedSdk.listTools()).tools.length, 1);
    await page.getByRole('button', {name: 'I saved it'}).click();
    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke client', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await assert.rejects(rotatedSdk.listTools(), 'Revocation immediately rejects the replacement token');
    await view('skills');
    await page.getByRole('button', {name: 'Import for review'}).click();
    await page.getByLabel('Skill name').fill('Browser reviewed skill');
    await page.getByLabel('Source reference').fill('local-e2e-fixture');
    await page.getByLabel('File map').fill(JSON.stringify({'SKILL.md': '# Reviewed skill\nUse explicit approval before writing.'}));
    await page.getByRole('button', {name: 'Preview import'}).click();
    await page.getByRole('heading', {name: 'Review import contents'}).waitFor();
    await page.getByRole('button', {name: 'Import unapproved skill'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('button', {name: 'Approve', exact: true}).click();
    await page.getByRole('button', {name: 'Approve files', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT approved FROM skill').get() as any).approved, 1);
    await page.getByRole('button', {name: 'Delete', exact: true}).click();
    await page.getByRole('button', {name: 'Delete skill', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM skill').get() as any).n, 0);
    await view('settings');
    await page.getByLabel('Audit retention').fill('45');
    await page.getByRole('button', {name: 'Save settings'}).click();
    await page.getByText('Settings saved.', {exact: true}).waitFor();
    assert.equal(hub.setting('audit_retention_days'), '45');
    if (process.env.HUB_CAPTURE_DASHBOARD === 'true') {
      const evidenceDir = fileURLToPath(new URL('../docs/evidence/', import.meta.url));
      await mkdir(evidenceDir, {recursive: true});
      await view('clients');
      await page.locator('#notice').waitFor({state: 'hidden'});
      if (await page.locator('html').getAttribute('data-theme') !== 'light') await page.locator('#theme-toggle').click();
      await page.screenshot({path: join(evidenceDir, 'dashboard-desktop.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844});
      if (await page.locator('html').getAttribute('data-theme') !== 'dark') await page.locator('#theme-toggle').click();
      await page.screenshot({path: join(evidenceDir, 'dashboard-mobile.png')});
      await page.setViewportSize({width: 1280, height: 900});
    }
    for (const [width, theme] of [[1280, 'light'], [390, 'dark']] as const) {
      await page.setViewportSize({width, height: 900});
      if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme-toggle').click();
      for (const pageName of ['overview', 'upstreams', 'tools', 'connections', 'profiles', 'clients', 'approvals', 'skills', 'security', 'audit', 'settings', 'backups']) {
        await view(pageName);
        assert.equal(await page.getByRole('heading', {name: 'Could not load this view'}).count(), 0, `${pageName} should load against the actual API`);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${pageName} ${width}px overflow`);
        if (process.env.HUB_CAPTURE_DASHBOARD === 'true' && pageName === 'overview') {
          const evidenceDir = fileURLToPath(new URL('../docs/evidence/', import.meta.url));
          await mkdir(evidenceDir, {recursive: true});
          await page.screenshot({path: join(evidenceDir, `overview-${width}-${theme}.png`), fullPage: true});
        }
      }
      const emptyBounds = await page.locator('main > .empty').boundingBox();
      const moveBounds = await page.locator('main > section').filter({has: page.getByRole('heading', {name: 'Move to another instance'})}).boundingBox();
      assert(emptyBounds && moveBounds && moveBounds.y > emptyBounds.y + emptyBounds.height, 'Backup empty-state and migration panel need a visible gap');
      if (process.env.HUB_CAPTURE_DASHBOARD === 'true') {
        const evidenceDir = fileURLToPath(new URL('../docs/evidence/', import.meta.url));
        await mkdir(evidenceDir, {recursive: true});
        await page.screenshot({path: join(evidenceDir, `backups-${width}-${theme}.png`), fullPage: true});
      }
    }
    await page.setViewportSize({width: 1280, height: 900});
    await page.getByRole('button', {name: 'Create encrypted backup'}).click();
    await page.getByLabel('Owner password').fill('Incorrect-browser-password-123');
    await page.getByRole('button', {name: 'Create backup', exact: true}).click();
    await page.getByRole('alert').filter({hasText: 'Password and MFA verification required'}).waitFor();
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Create backup', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByText('Encrypted backup', {exact: true}).waitFor();
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', {name: 'Export config'}).click();
    const download = await downloadPromise;
    assert.equal(download.suggestedFilename(), 'wheremymcp-config.json');
    const path = await download.path(); assert(path);
    assert(!(await readFile(path, 'utf8')).includes('credential-canary-browser'));
    const encryptedDownload = page.waitForEvent('download');
    await page.getByRole('button', {name: 'Download encrypted backup', exact: true}).click();
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Download backup file'}).click();
    const backupDownload = await encryptedDownload;
    const backupPath = await backupDownload.path(); assert(backupPath);
    assert.match(backupDownload.suggestedFilename(), /\.umcp$/);
    assert(JSON.parse(await readFile(backupPath, 'utf8')).ciphertext);
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    const importedId = randomUUID();
    const importFixture = {format: 2, profiles: [{id: importedId, name: 'Browser imported', slug: 'browser-imported', is_default: 0}], connections: [], upstreams: [], tools: [], grants: [], skills: []};
    await page.getByRole('button', {name: 'Import config', exact: true}).click();
    await page.getByLabel('Read export JSON file').setInputFiles({name: 'config.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(importFixture))});
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Preview config import'}).click();
    await page.getByRole('heading', {name: 'Review configuration import'}).waitFor();
    assert.equal(hub.db.prepare('SELECT id FROM profile WHERE id=?').get(importedId), undefined);
    await page.getByRole('button', {name: 'Import reviewed configuration'}).click();
    await page.getByRole('heading', {name: 'Configuration import result'}).waitFor();
    assert(hub.db.prepare('SELECT id FROM profile WHERE id=?').get(importedId));
    await page.getByRole('button', {name: 'Done', exact: true}).click();
    await view('audit');
    await page.getByText('Filter policy events', {exact: true}).click();
    await page.getByLabel('Action', {exact: true}).fill('client.rotate');
    await page.getByRole('button', {name: 'Apply filters'}).click();
    await page.getByText('client.rotate', {exact: true}).waitFor();
    await view('connections');
    await page.getByRole('button', {name: 'Delete', exact: true}).click();
    await page.getByRole('button', {name: 'Delete connection', exact: true}).click();
    await page.locator('#notice').filter({hasText: 'Connection is bound to an MCP server'}).waitFor();
    assert(hub.db.prepare('SELECT id FROM connection WHERE id=?').get(connection.id), 'A rejected delete keeps the connection intact');
    await page.getByRole('button', {name: 'Cancel', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke connection', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal((hub.db.prepare('SELECT status FROM connection WHERE id=?').get(connection.id) as any).status, 'revoked');
    await view('upstreams');
    await page.getByRole('button', {name: 'Delete', exact: true}).click();
    await page.getByRole('button', {name: 'Delete server', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal(hub.db.prepare('SELECT id FROM tool WHERE id=?').get(toolId), undefined);
    assert.equal((hub.db.prepare('SELECT COUNT(*) AS n FROM profile_grant WHERE tool_id=?').get(toolId) as any).n, 0);
    await view('connections');
    await page.getByRole('button', {name: 'Delete', exact: true}).click();
    await page.getByRole('button', {name: 'Delete connection', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.equal(hub.db.prepare('SELECT id FROM connection WHERE id=?').get(connection.id), undefined);
    await view('security');
    await page.getByRole('button', {name: 'Stop all gateway calls'}).click();
    await page.getByRole('button', {name: 'Stop all calls', exact: true}).click();
    await page.getByText('All gateway tool calls are stopped.', {exact: true}).waitFor();
    assert.equal(hub.setting('emergency_stop'), 'true');
    await page.getByRole('button', {name: 'Replace recovery codes'}).click();
    await page.getByLabel('Owner password').fill('Local-browser-password-123');
    await page.getByRole('button', {name: 'Generate replacement codes'}).click();
    await page.getByRole('heading', {name: 'Save replacement recovery codes'}).waitFor();
    await page.getByRole('button', {name: 'I saved it'}).click();
    await page.getByRole('button', {name: 'Change owner password'}).click();
    await page.getByLabel('Current owner password').fill('Local-browser-password-123');
    await page.getByLabel('New owner password').fill('Changed-browser-password-456');
    await page.getByRole('button', {name: 'Save new password'}).click();
    await page.getByRole('heading', {name: 'Owner login'}).waitFor();
    await page.getByLabel('Owner password').fill('Changed-browser-password-456');
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.getByRole('heading', {name: 'Owner authenticator'}).waitFor();
    await page.waitForTimeout(4000);
    await page.getByRole('button', {name: 'Set up MFA'}).click();
    await page.getByRole('heading', {name: 'Set up your authenticator'}).waitFor();
    const { TOTP, Secret } = await import('otpauth');
    const secret = await page.getByRole('dialog').locator('pre').first().innerText();
    const totp = new TOTP({secret: Secret.fromBase32(secret)});
    await page.getByLabel('Authenticator code').fill(totp.generate());
    await page.getByRole('button', {name: 'Enable MFA'}).click();
    await page.getByText('MFA is enabled for this owner.', {exact: true}).waitFor();
    assert.equal((hub.db.prepare('SELECT mfa_enabled FROM owner').get() as any).mfa_enabled, 1);
    await page.getByRole('button', {name: 'Disable MFA'}).click();
    await page.getByLabel('Owner password').fill('Changed-browser-password-456');
    await page.getByLabel('Current authenticator code').fill(totp.generate({timestamp: Date.now() + 30_000}));
    await page.getByRole('dialog').getByRole('button', {name: 'Disable MFA'}).click();
    await page.getByRole('heading', {name: 'Owner login'}).waitFor();
    assert.equal((hub.db.prepare('SELECT mfa_enabled FROM owner').get() as any).mfa_enabled, 0);
    await page.getByLabel('Owner password').fill('Changed-browser-password-456');
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.getByRole('heading', {name: 'Owner authenticator'}).waitFor();
    hub.db.prepare('UPDATE session SET expires_at=0').run();
    await view('settings');
    await page.getByRole('heading', {name: 'Owner login'}).waitFor();
    await page.getByLabel('Owner password').fill('Changed-browser-password-456');
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.getByRole('heading', {name: 'Settings & diagnostics'}).waitFor();
    const unauthenticatedConnection=randomUUID(),unauthenticatedServer=randomUUID();
    hub.db.prepare('INSERT INTO connection(id,provider,alias,status,created_at) VALUES(?,?,?,?,?)').run(unauthenticatedConnection,'bearer','needs-authorization','not_configured',Date.now());
    hub.db.prepare('INSERT INTO upstream(id,name,url,connection_id,status,created_at) VALUES(?,?,?,?,?,?)').run(unauthenticatedServer,'Needs authorization','https://example.com/mcp',unauthenticatedConnection,'pending_review',Date.now());
    await view('upstreams');
    await page.locator('article').filter({has:page.getByRole('heading',{name:'Needs authorization',exact:true})}).getByRole('button',{name:'Auto approve tools',exact:true}).click();
    await page.getByRole('checkbox',{name:'I trust the selected servers to describe their tools',exact:true}).check();
    await page.getByRole('dialog').getByRole('button',{name:'Auto approve tools',exact:true}).click();
    const failedApproval=page.getByRole('dialog');await failedApproval.getByRole('heading',{name:'Tool approval needs attention',exact:true}).waitFor();
    assert.match(await failedApproval.innerText(),/Open Connections, authorize or update its account/);
    assert.equal(await failedApproval.getByRole('button',{name:'Choose client tool access',exact:true}).count(),0);
    assert.match(await failedApproval.innerText(),/No new tool access was granted/);
    if(process.env.HUB_CAPTURE_DASHBOARD==='true')for(const [width,theme] of [[1280,'light'],[390,'dark']] as const){
      await page.setViewportSize({width,height:900});await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
      assert.equal(await failedApproval.evaluate(node=>node.scrollWidth<=node.clientWidth),true);
      await failedApproval.screenshot({path:fileURLToPath(new URL(`../docs/evidence/tool-approval-auth-error-${width}.png`,import.meta.url))});
    }
    await failedApproval.getByRole('button',{name:'Review connections',exact:true}).click();await failedApproval.waitFor({state:'hidden'});
    await page.getByRole('heading',{name:'Connections',exact:true}).waitFor();
    hub.db.prepare('DELETE FROM upstream WHERE id=?').run(unauthenticatedServer);hub.db.prepare('DELETE FROM connection WHERE id=?').run(unauthenticatedConnection);
    await page.setViewportSize({width:1280,height:900});
    const accessServer=randomUUID(),accessProfile=randomUUID(),accessClient=randomUUID(),accessTools:string[]=[];
    hub.db.prepare('INSERT INTO upstream(id,name,url,status,created_at) VALUES(?,?,?,?,?)').run(accessServer,'Project workspace','https://example.com/mcp','active',Date.now());
    hub.db.prepare('INSERT INTO profile VALUES(?,?,?,?,?)').run(accessProfile,'Research assistant','research-ui',0,Date.now());
    hub.db.prepare('INSERT INTO client(id,name,kind,profile_id,token_hash,created_at) VALUES(?,?,?,?,?,?)').run(accessClient,'Research desktop','codex',accessProfile,randomUUID(),Date.now());
    for(let i=0;i<30;i++){
      const id=randomUUID();accessTools.push(id);const name=i===0?'search_projects':i===1?'lookup_'+('long_project_name_'.repeat(12)):i===29?'unreviewed_tool':`lookup_record_${i}`;
      hub.db.prepare('INSERT INTO tool(id,upstream_id,name,gateway_name,description,input_schema,fingerprint,approved_fingerprint,risk,enabled) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,accessServer,name,`u_${accessServer.replaceAll('-','')}__${'f'.repeat(62)}${String(i).padStart(2,'0')}`,'Find project information in the workspace.','{}','reviewed',i===29?null:'reviewed',i===29?'unreviewed':'read',i===29?0:1);
    }
    hub.db.prepare('INSERT INTO profile_grant VALUES(?,?,NULL,?)').run(accessProfile,accessTools[0],'read');
    const longDescription='Search project records in this workspace. '+('Use filters to narrow results and return matching project details. '.repeat(4))+"<examples>search_projects(query='active projects')\nsearch_projects(query='recent updates')</examples><hints>Choose exact filters when needed. <img src=x onerror=alert(1)></hints>";
    hub.db.prepare('UPDATE tool SET description=? WHERE id=?').run(longDescription,accessTools[0]);
    await view('tools');
    await page.getByRole('searchbox',{name:'Search tools',exact:true}).fill('search_projects');
    const descriptionRow=page.locator('article').filter({has:page.getByRole('heading',{name:'search_projects',exact:true})});
    assert.equal(await descriptionRow.locator('.tool-description-preview').innerText(),'Search project records in this workspace.');
    const usage=descriptionRow.locator('.tool-description > details');
    await page.locator('#notice').waitFor({state:'hidden'});
    for(const width of [1280,390]){
      await page.setViewportSize({width,height:900});
      for(const theme of ['light','dark']){
        await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
        assert.equal(await usage.getAttribute('open'),null,'Long server descriptions must start collapsed');
        assert.equal((await descriptionRow.innerText()).includes('<examples>'),false);
        if(process.env.HUB_CAPTURE_DASHBOARD==='true'&&theme==='light')await descriptionRow.screenshot({path:fileURLToPath(new URL(`../docs/evidence/tool-description-${width}.png`,import.meta.url))});
        await usage.locator('summary').focus();await page.keyboard.press('Enter');
        await usage.locator('h4').first().waitFor();
        assert.equal(await usage.getByRole('heading',{name:'Examples',exact:true}).isVisible(),true);
        assert.equal(await usage.getByRole('heading',{name:'Usage notes',exact:true}).isVisible(),true);
        assert.equal(await descriptionRow.locator('img,script').count(),0,'Server descriptions must remain text, never HTML');
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Expanded examples must wrap on mobile');
        if(process.env.HUB_CAPTURE_DASHBOARD==='true'&&theme==='dark')await descriptionRow.screenshot({path:fileURLToPath(new URL(`../docs/evidence/tool-description-expanded-${width}.png`,import.meta.url))});
        await usage.locator('summary').focus();await page.keyboard.press('Enter');
      }
    }
    await page.setViewportSize({width:1280,height:900});
    await view('profiles');
    const research=()=>page.locator('article').filter({has:page.getByRole('heading',{name:'Research assistant',exact:true})});
    await research().getByRole('button',{name:'Edit tool access'}).click();
    const grantDialog=page.getByRole('dialog');
    await grantDialog.getByRole('heading',{name:'Tool access: Research assistant'}).waitFor();
    assert.equal(await grantDialog.locator('.grant-entry').filter({has:page.getByRole('checkbox',{name:'Allow search_projects',exact:true})}).locator('.grant-description').innerText(),'Search project records in this workspace.');
    assert.equal(await grantDialog.getByRole('checkbox',{name:'Allow search_projects',exact:true}).isChecked(),true);
    assert.equal(await grantDialog.getByRole('checkbox',{name:'Allow unreviewed_tool',exact:true}).isDisabled(),true);
    assert.equal((await grantDialog.innerText()).includes(`u_${accessServer.replaceAll('-','')}__`),false,'Machine identifiers must not be primary grant labels');
    for(const width of [1280,390]){
      await page.setViewportSize({width,height:900});
      for(const theme of ['light','dark']){
        await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
        assert.equal(await grantDialog.evaluate(node=>node.scrollWidth<=node.clientWidth),true,'Grant dialog must not overflow horizontally');
        assert.equal(await grantDialog.locator('.dialog-body').evaluate(node=>node.scrollWidth<=node.clientWidth),true,'Grant list must wrap long names');
        assert.equal(await grantDialog.evaluate(node=>{const box=node.getBoundingClientRect();return box.left>=0&&box.right<=innerWidth&&box.top>=0&&box.bottom<=innerHeight;}),true,'Grant dialog must stay inside viewport');
        await grantDialog.locator('.dialog-body').evaluate(node=>node.scrollTop=node.scrollHeight);
        assert.equal(await grantDialog.getByRole('button',{name:'Save access',exact:true}).isVisible(),true);
        const saveBox=await grantDialog.getByRole('button',{name:'Save access',exact:true}).boundingBox();assert(saveBox&&saveBox.y+saveBox.height<=900,'Save must remain visible while scrolling');
        if(process.env.HUB_CAPTURE_DASHBOARD==='true'){await mkdir(new URL('../docs/evidence/',import.meta.url),{recursive:true});await page.screenshot({path:fileURLToPath(new URL(`../docs/evidence/grants-${width}-${theme}.png`,import.meta.url))});}
      }
    }
    await page.setViewportSize({width:1280,height:900});
    await grantDialog.getByRole('searchbox',{name:'Search tools',exact:true}).fill('search_projects');
    assert.equal(await grantDialog.locator('.grant-entry:visible').count(),1);
    await grantDialog.getByRole('checkbox',{name:'Allow search_projects',exact:true}).uncheck();
    await grantDialog.getByRole('button',{name:'Save access',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    assert.equal(hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(accessProfile),0,'Unchecking must remove the stored grant');
    await research().getByRole('button',{name:'Edit tool access'}).click();
    await grantDialog.getByRole('checkbox',{name:'Allow search_projects',exact:true}).check();
    await grantDialog.getByRole('button',{name:'Clear selection',exact:true}).click();
    assert.equal(await grantDialog.getByRole('checkbox',{checked:true}).count(),0);
    await grantDialog.getByRole('button',{name:'Save access',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    await research().getByRole('button',{name:'Delete profile',exact:true}).click();
    const fallback=(hub.db.prepare('SELECT id FROM profile WHERE is_default=1').get() as {id:string}).id;
    await grantDialog.getByLabel('Move clients to profile').selectOption(fallback);
    await grantDialog.getByRole('button',{name:'Move clients and delete profile',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    assert.equal(hub.db.prepare('SELECT id FROM profile WHERE id=?').get(accessProfile),undefined);
    assert.equal((hub.db.prepare('SELECT profile_id FROM client WHERE id=?').get(accessClient) as {profile_id:string}).profile_id,fallback);
    await page.getByRole('heading',{name:'Research assistant',exact:true}).waitFor({state:'hidden'});
    await page.getByRole('button',{name:'Create profile',exact:true}).click();
    await grantDialog.getByLabel('Profile name').fill('Disposable profile');
    await grantDialog.getByRole('button',{name:'Create profile',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    const unused=(hub.db.prepare('SELECT id FROM profile WHERE name=?').get('Disposable profile') as {id:string}).id;
    await page.locator('article').filter({has:page.getByRole('heading',{name:'Disposable profile',exact:true})}).getByRole('button',{name:'Delete profile',exact:true}).click();
    await grantDialog.getByRole('button',{name:'Delete profile',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    assert.equal(hub.db.prepare('SELECT id FROM profile WHERE id=?').get(unused),undefined);
    const scaleStarted=performance.now();
    hub.db.prepare('DELETE FROM upstream').run();
    scaleManifest=Array.from({length:50},(_,i)=>({name:`workspace_tool_${i}`,description:'Workspace action supplied by the trusted test server.',inputSchema:{type:'object',properties:{text:{type:'string'}},required:['text']},annotations:i%3===0?{readOnlyHint:true}:i%3===2?{destructiveHint:true}:{}}));
    const sessionData=await (await page.request.get(config.origin+'/auth/session')).json();
    const ownerHeaders={'x-csrf-token':sessionData.csrf_token};
    assert.equal((await page.request.post(config.origin+'/api/v1/emergency-stop',{headers:ownerHeaders,data:{enabled:false}})).status(),200);
    const accountResponse=await page.request.post(config.origin+'/api/v1/connections',{headers:ownerHeaders,data:{provider:'bearer',alias:'scale-fixture',secret:'credential-canary-browser'}});assert.equal(accountResponse.status(),201);
    const scaleAccount=(await accountResponse.json()).connection.id;
    for(let i=1;i<=50;i++){
      const response=await page.request.post(config.origin+'/api/v1/upstreams',{headers:ownerHeaders,data:{name:`Scale MCP ${String(i).padStart(2,'0')}`,url:`http://127.0.0.1:${upstreamAddress.port}/mcp`,allowed_private_ips:['127.0.0.1'],connection_id:scaleAccount}});
      assert.equal(response.status(),200,`Server ${i} must register beyond the former 32-server limit`);
    }
    await view('upstreams');
    await page.getByRole('checkbox',{name:'Select all servers',exact:true}).check();
    await page.getByRole('button',{name:'Auto approve selected servers',exact:true}).click();
    await grantDialog.getByRole('checkbox',{name:'I trust the selected servers to describe their tools',exact:true}).check();
    await grantDialog.getByRole('button',{name:'Auto approve tools',exact:true}).click();
    await grantDialog.getByRole('heading',{name:'Tool approval results',exact:true}).waitFor({timeout:90000});
    assert.match(await grantDialog.innerText(),/Enabled 2500 tools across 50 servers/);
    assert.equal(hub.db.prepare('SELECT count(*) FROM tool WHERE enabled=1').pluck().get(),2500);
    const readyCounts=(await (await page.request.get(config.origin+'/api/v1/overview')).json()).counts;assert.equal(readyCounts.enabled_tools,2500);assert.equal(readyCounts.grants,0);
    assert.deepEqual(hub.db.prepare('SELECT risk,count(*) AS n FROM tool GROUP BY risk ORDER BY risk').all(),[{risk:'delete',n:800},{risk:'read',n:850},{risk:'write',n:850}]);
    await grantDialog.getByRole('button',{name:'Done',exact:true}).click();
    const scaleProfile=randomUUID();hub.db.prepare('INSERT INTO profile VALUES(?,?,?,?,?)').run(scaleProfile,'All workspaces','scale-workspaces',0,Date.now());
    await view('profiles');
    const scaleCard=()=>page.locator('article').filter({has:page.getByRole('heading',{name:'All workspaces',exact:true})});
    await scaleCard().getByRole('button',{name:'Edit tool access',exact:true}).click();
    await grantDialog.getByRole('heading',{name:'Tool access: All workspaces',exact:true}).waitFor({timeout:15000});
    assert.equal(await grantDialog.locator('.grant-group').count(),50);
    assert.equal(await grantDialog.locator('.grant-group details[open]').count(),0,'Large registries start collapsed by server');
    await grantDialog.getByRole('checkbox',{name:'Allow all tools from Scale MCP 01',exact:true}).check();
    assert.match(await grantDialog.locator('.dialog-footer').innerText(),/50 tools selected/);
    await grantDialog.getByRole('button',{name:'Save access',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    assert.equal(hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(scaleProfile),50,'One server selection grants all 50 tools');
    await scaleCard().getByRole('button',{name:'Edit tool access',exact:true}).click();
    await grantDialog.getByRole('button',{name:'Select all available',exact:true}).click();
    assert.match(await grantDialog.locator('.dialog-footer').innerText(),/2500 tools selected/);
    for(const width of [1280,390]){
      await page.setViewportSize({width,height:900});
      assert.equal(await grantDialog.evaluate(node=>node.scrollWidth<=node.clientWidth&&node.getBoundingClientRect().left>=0&&node.getBoundingClientRect().right<=innerWidth),true);
      if(process.env.HUB_CAPTURE_DASHBOARD==='true')await page.screenshot({path:fileURLToPath(new URL(`../docs/evidence/bulk-access-${width}.png`,import.meta.url))});
    }
    await page.setViewportSize({width:1280,height:900});
    await grantDialog.getByRole('button',{name:'Save access',exact:true}).click();await grantDialog.waitFor({state:'hidden'});
    assert.equal(hub.db.prepare('SELECT count(*) FROM profile_grant WHERE profile_id=?').pluck().get(scaleProfile),2500,'One bulk selection persists all 2500 grants');
    const scaleClientResponse=await page.request.post(config.origin+'/api/v1/clients',{headers:ownerHeaders,data:{name:'Scale agent',kind:'codex',profile_id:scaleProfile}});assert.equal(scaleClientResponse.status(),201);
    const scaleToken=(await scaleClientResponse.json()).token;
    const scaleSdk=new Client({name:'scale-browser',version:'1'});sdkClients.push(scaleSdk);
    await scaleSdk.connect(new StreamableHTTPClientTransport(new URL(config.origin+'/mcp'),{requestInit:{headers:{authorization:`Bearer ${scaleToken}`}}}));
    assert.equal((await scaleSdk.listTools()).tools.length,2500,'A real SDK client receives the selected registry');
    const scaleReport={fixture:'50 registered MCP entries backed by one authenticated local MCP fixture',servers:50,tools_per_server:50,enabled_tools:2500,saved_grants:2500,sdk_visible_tools:2500,bulk_concurrency:4,elapsed_ms:Math.round(performance.now()-scaleStarted)};
    if(process.env.HUB_CAPTURE_DASHBOARD==='true')await writeFile(new URL('../docs/evidence/bulk-setup-scale.json',import.meta.url),JSON.stringify(scaleReport,null,2)+'\n');
    await view('tools');
    assert.equal(await page.locator('main .row-title').count(),50,'Manual review initially renders only 50 tools');
    await page.getByRole('button',{name:'Show 50 more tools',exact:true}).click();assert.equal(await page.locator('main .row-title').count(),100);
    const scaleFirst=(hub.db.prepare('SELECT id FROM upstream WHERE name=?').get('Scale MCP 01') as {id:string}).id;
    await page.getByRole('combobox',{name:'Filter tools by server',exact:true}).selectOption(scaleFirst);
    assert.equal(await page.locator('main .row-title').count(),50);assert.equal(await page.getByRole('button',{name:'Show 50 more tools',exact:true}).isVisible(),false);
    await page.getByRole('button', {name: 'Log out', exact: true}).click();
    await page.getByRole('heading', {name: 'Owner login'}).waitFor();
    assert.deepEqual(errors, []);
  } finally {
    await Promise.all(sdkClients.map(client => client.close().catch(() => {})));
    if (browser) await browser.close();
    await app.close(); await upstreamHandler.close(); upstreamServer.closeAllConnections();
    await new Promise<void>(resolve => upstreamServer.close(() => resolve()));
    hub.close(); await rm(dir, {recursive: true, force: true});
  }
});

test('dashboard ships same-origin scripts, labeled navigation, and both themes', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const css = await readFile(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(html, /type="module" src="\/app.js"/);
  assert.match(html, /href="#main"/);
  assert.match(css, /data-theme="dark"/);
  assert.match(css, /focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
});

test('browser owner workflows, XSS boundaries, responsive themes and one-time secrets', {timeout: 90000}, async t => {
  const calls: {path: string; method: string; body: any; csrf?: string; query?: string}[] = [];
  let claimed = false;
  let loggedIn = false;
  let stopped = false;
  let mfa = false;
  let overviewFailures = 1;
  const profiles = [{id: 'p1', name: 'Owner profile', slug: 'owner', is_default: 1}];
  const tools = [{id: 't1', upstream_id: 'u1', connection_id: 'c1', name: 'write_note', gateway_name: 'notes__write_note', description: '<img src=x onerror=window.pwned=true>', risk: 'write', enabled: 1, input_schema: {type: 'object'}, annotations: {}, fingerprint: 'new-fingerprint', approved_fingerprint: 'old-fingerprint', previous_metadata: {description: 'Prior description', input_schema: {type: 'object', properties: {text: {type: 'string'}}}, annotations: {}, fingerprint: 'old-fingerprint'}}];
  let upstreamStatus = 'pending_review';
  const connections = [{id: 'c1', provider: 'google', alias: 'Work account', identity: 'owner@example.test', scopes: ['notes.write'], status: 'active'}];
  const clients = [{id: 'client1', name: 'Editor client', profile_id: 'p1', kind: 'codex', status: 'active'}];
  const skills: any[] = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, 'http://localhost');
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/') || url.pathname === '/setup/claim') {
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = raw ? JSON.parse(raw) : undefined;
      calls.push({path: url.pathname, method: req.method!, body, csrf: req.headers['x-csrf-token'] as string | undefined, query: url.search});
      if (url.pathname === '/api/v1/overview' && overviewFailures-- > 0) {
        res.statusCode = 503; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({message: 'Test instance temporarily unavailable'})); return;
      }
      let data: any = {};
      if (url.pathname === '/api/v1/setup') data = {claimed, public_mode: false};
      else if (url.pathname === '/setup/claim') { claimed = true; data = {recovery_codes: ['recovery-one', 'recovery-two']}; }
      else if (url.pathname === '/auth/session') { if (req.method === 'POST') loggedIn = true; data = {authenticated: loggedIn, csrf_token: loggedIn ? 'csrf-browser-test' : undefined, mfa_enabled: mfa}; }
      else if (url.pathname === '/auth/logout') loggedIn = false;
      else if (url.pathname === '/api/v1/overview') data = {counts: {clients: clients.length, tools: tools.length}, emergency_stop: stopped, recent_events: []};
      else if (url.pathname === '/api/v1/emergency-stop') stopped = body.enabled;
      else if (url.pathname === '/api/v1/upstreams') data = req.method === 'POST' ? {upstream: body} : {upstreams: [{id: 'u1', name: 'Notes server', url: 'https://notes.example.test/mcp', status: upstreamStatus, connection_id: 'c1', timeout_ms: 15000, allowed_private_ips: []}]};
      else if (url.pathname === '/api/v1/upstreams/u1/approve') upstreamStatus = 'active';
      else if (url.pathname === '/api/v1/upstreams/u1/disable') { upstreamStatus = 'disabled'; data = {upstream: {status: 'disabled'}}; }
      else if (url.pathname === '/api/v1/tools') data = {tools};
      else if (url.pathname === '/api/v1/connections') data = {connections};
      else if (url.pathname.endsWith('/oauth/start')) data = {authorization_url: 'https://accounts.example.test/authorize?state=test'};
      else if (url.pathname === '/api/v1/profiles') { if (req.method === 'POST') profiles.push({id: 'p2', ...body}); data = {profiles}; }
      else if (url.pathname === '/api/v1/profiles/p1') data = {...profiles[0], grants: [{tool_id: 't1', connection_id: 'c1', action_class: 'write'}]};
      else if (url.pathname === '/api/v1/clients') data = req.method === 'POST' ? {client: body, token: 'created-token-once'} : {clients};
      else if (url.pathname.endsWith('/rotate')) data = {token: 'rotated-token-once'};
      else if (url.pathname.endsWith('/config')) data = {snippet: 'token = "${WHEREMYMCP_TOKEN}"', instructions: 'Set WHEREMYMCP_TOKEN in your environment.'};
      else if (url.pathname === '/api/v1/approvals') data = {approval_id: 'approval-once'};
      else if (url.pathname === '/api/v1/skills') {
        if (req.method === 'POST') skills.push({id: 's1', ...body, content: body.files, digest: 'digest-1', approved: false});
        data = {skills};
      }
      else if (url.pathname === '/auth/mfa/setup') data = {secret: 'AUTHENTICATOR-SETUP-SECRET', uri: 'otpauth://totp/WhereMyMCP?secret=TEST'};
      else if (url.pathname === '/auth/mfa/enable') mfa = true;
      else if (url.pathname === '/auth/mfa/disable') mfa = false;
      else if (url.pathname === '/api/v1/audit') {
        const older = url.searchParams.has('cursor');
        data = {events: [{id: older ? 'a2' : 'a1', ts: 100, principal: 'client1', profile_id: 'p1', account_id: 'c1', account_alias: 'old-work-account', action: 'tool.call', outcome: 'denied', resource: 't1', detail: older ? 'second_same_timestamp' : 'approval_required'}], next_before: older ? null : 100, next_cursor: older ? null : 'cursor-event-one'};
      }
      else if (url.pathname === '/api/v1/backups') data = {backups: []};
      else if (url.pathname === '/api/v1/backup/create') data = {name: 'backup.enc', created_at: Date.now(), size: 500};
      else if (url.pathname === '/api/v1/config/export') data = {version: 1, profiles};
      else if (url.pathname === '/api/v1/settings') data = {audit_retention_days: 90};
      else if (url.pathname === '/api/v1/system/diagnostics') data = {database: 'ok', migrations: 'current', public_mode: false};
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(data)); return;
    }
    try {
      const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (!['index.html', 'styles.css', 'app.js'].includes(file)) throw new Error('missing');
      res.setHeader('content-type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
      res.end(await readFile(new URL(`../public/${file}`, import.meta.url)));
    } catch { res.statusCode = 404; res.end(); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage({viewport: {width: 1365, height: 900}});
  page.setDefaultTimeout(7000);
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const address = server.address();
  assert(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], {origin});
  async function view(name: string) { await page.goto(`${origin}/#${name}`); await page.locator('main[aria-busy="false"]').waitFor(); }
  async function close() { await page.getByRole('dialog').getByRole('button', {name: 'Close', exact: true}).click(); }
  try {
    await page.goto(origin);
    await page.getByLabel('Setup token').fill('bootstrap-local');
    await page.getByLabel('Owner password').fill('A-unique-password-123');
    await page.getByRole('button', {name: 'Create owner account'}).click();
    await page.getByRole('heading', {name: 'Save your recovery codes'}).waitFor();
    assert.match(await page.getByRole('dialog').innerText(), /recovery-one/);
    await page.getByRole('button', {name: 'I saved it'}).click();
    await page.getByLabel('Owner password').fill('A-unique-password-123');
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.getByRole('heading', {name: 'Could not load this view'}).waitFor();
    await page.getByRole('button', {name: 'Retry loading'}).click();
    await page.getByRole('heading', {name: 'Gateway policy is active'}).waitFor();
    await page.reload();
    await page.getByRole('heading', {name: 'Gateway policy is active'}).waitFor();
    await page.getByRole('button', {name: 'Emergency stop', exact: true}).click();
    await page.getByRole('button', {name: 'Stop all calls', exact: true}).click();
    await page.getByRole('heading', {name: 'Gateway calls are stopped'}).waitFor();
    await page.getByRole('button', {name: 'Resume gateway calls'}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Resume calls', exact: true}).click();
    await page.getByRole('heading', {name: 'Gateway policy is active'}).waitFor();
    await view('tools');
    assert.match(await page.locator('main').innerText(), /<img src=x onerror/);
    assert.equal(await page.evaluate(() => (window as any).pwned), undefined);
    assert.equal(await page.locator('main img').count(), 0);
    await page.getByRole('heading', {name: 'Previously approved'}).waitFor();
    await page.getByText('Current schema, annotations & fingerprint', {exact: true}).click();
    await page.getByRole('button', {name: 'Review tool'}).click();
    await page.getByRole('dialog').getByLabel('Tool behavior').selectOption('write');
    await page.getByRole('button', {name: 'Enable tool'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await view('profiles');
    await page.getByRole('button', {name: 'Edit tool access'}).first().click();
    await page.getByRole('button', {name: 'Save access'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert.deepEqual(calls.find(call => call.path.endsWith('/grants'))?.body.grants, [{tool_id: 't1', connection_id: 'c1', action_class: 'write'}]);
    await view('clients');
    await page.getByRole('button', {name: 'Issue client token'}).click();
    await page.getByRole('dialog').getByLabel('Client name').fill('New local client');
    await page.getByRole('button', {name: 'Issue token', exact: true}).click();
    await page.getByRole('heading', {name: 'Save client token'}).waitFor();
    assert.match(await page.getByRole('dialog').innerText(), /created-token-once/);
    await page.getByRole('dialog').getByRole('button', {name: 'Copy token', exact: true}).click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'created-token-once');
    await page.getByRole('button', {name: 'I saved it'}).click();
    await page.getByRole('button', {name: 'Rotate token', exact: true}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Rotate token', exact: true}).click();
    await page.getByRole('heading', {name: 'Save replacement token'}).waitFor();
    assert.match(await page.getByRole('dialog').innerText(), /rotated-token-once/);
    await close();
    await page.getByRole('button', {name: 'Client config', exact: true}).click();
    await page.getByRole('button', {name: 'Generate config', exact: true}).click();
    await page.getByRole('heading', {name: 'Client configuration'}).waitFor();
    assert.match(await page.getByRole('dialog').innerText(), /WHEREMYMCP_TOKEN/);
    await page.getByRole('button', {name: 'Copy config', exact: true}).click();
    assert.match(await page.evaluate(() => navigator.clipboard.readText()), /WHEREMYMCP_TOKEN/);
    await close();
    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Cancel', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke client', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await view('upstreams');
    await page.getByRole('button', {name: 'Refresh tools', exact: true}).click();
    await page.getByRole('button', {name: 'Approve server', exact: true}).click();
    await page.getByRole('dialog').getByRole('button', {name: 'Approve server', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});

    await page.getByRole('button', {name: 'Disable', exact: true}).click();
    await page.getByRole('button', {name: 'Disable server', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('button', {name: 'Register server', exact: true}).click();
    await page.getByLabel('Server name').fill('Private notes');
    await page.getByLabel('Remote MCP URL').fill('https://notes.example.test/mcp');
    await page.getByLabel('Explicit local IP allowlist').fill('["10.0.0.0/8"]');
    await page.getByRole('dialog').getByRole('button', {name: 'Register server'}).click();
    await page.getByRole('alert').filter({hasText: 'exact IP'}).waitFor();
    await page.getByLabel('Explicit local IP allowlist').fill('["127.0.0.1"]');
    await page.getByRole('dialog').getByRole('button', {name: 'Register server'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await view('connections');
    await page.getByRole('button', {name: 'Edit connection'}).click();
    await page.getByLabel('Account alias').fill('work-account');
    await page.getByLabel('Replacement secret').fill('new-canary-credential');
    await page.getByRole('button', {name: 'Save connection'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('button', {name: 'Connect OAuth'}).click();
    await page.getByRole('link', {name: 'Open provider authorization'}).waitFor();
    await page.keyboard.press('Escape');
    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke connection', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('button', {name: 'Add connection', exact: true}).click();
    await page.getByLabel('Credential provider').selectOption('remote_oauth');
    await page.getByLabel('Account alias').fill('remote-public-account');
    await page.getByRole('button', {name: 'Create connection', exact: true}).click();
    await page.getByRole('alert').filter({hasText: 'Remote OAuth requires'}).waitFor();
    await page.getByLabel('Provider configuration').fill(JSON.stringify({client_id: 'public-test', issuer: 'https://auth.example.test', resource: 'https://mcp.example.test/mcp', allowed_origin: 'https://mcp.example.test'}));
    await page.getByRole('button', {name: 'Create connection', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    assert(calls.some(call => call.path === '/api/v1/connections' && call.body?.provider === 'remote_oauth' && !call.body.secret));
    await view('approvals');
    await page.locator('#field-client_id').selectOption('client1');
    await page.getByLabel('Write or delete tool').selectOption('t1');
    await page.getByRole('button', {name: 'Approve one call'}).click();
    await page.getByRole('heading', {name: 'One-use call approval'}).waitFor();
    await close();
    await view('skills');
    await page.getByRole('button', {name: 'Import for review'}).click();
    await page.getByLabel('Skill name').fill('Notes policy');
    await page.getByLabel('Source reference').fill('local-review');
    await page.getByLabel('File map').fill(JSON.stringify({'SKILL.md': '# Notes\nReview before writing.'}));
    await page.getByRole('button', {name: 'Preview import'}).click();
    await page.getByRole('heading', {name: 'Review import contents'}).waitFor();
    await page.getByText('SKILL.md', {exact: true}).click();
    await page.getByRole('button', {name: 'Import unapproved skill'}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('heading', {name: 'Notes policy'}).waitFor();
    await page.getByRole('button', {name: 'Approve', exact: true}).click();
    await page.getByRole('button', {name: 'Approve files', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await page.getByRole('button', {name: 'Delete', exact: true}).click();
    await page.getByRole('button', {name: 'Delete skill', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await view('security');
    await page.getByRole('button', {name: 'Set up MFA'}).click();
    await page.locator('#field-totp').fill('123456');
    await page.getByRole('button', {name: 'Enable MFA'}).click();
    await page.getByText('MFA is enabled for this owner.', {exact: true}).waitFor();
    await view('audit');
    await page.getByText('Filter policy events', {exact: true}).click();
    await page.getByLabel('Principal / client ID').fill('client1');
    await page.getByLabel('Historical profile ID').fill('p1');
    await page.getByLabel('Account alias at event').fill('old-work-account');
    await page.getByRole('button', {name: 'Apply filters'}).click();
    await page.getByText('approval_required', {exact: true}).waitFor();
    await page.getByText('Account at event: old-work-account', {exact: true}).waitFor();
    await page.getByRole('button', {name: 'Load older events'}).click();
    await page.getByText('second_same_timestamp', {exact: true}).waitFor();
    assert(calls.some(call => call.path === '/api/v1/audit' && call.query?.includes('cursor=cursor-event-one')));
    assert(calls.some(call => call.path === '/api/v1/audit' && call.query?.includes('profile_id=p1') && call.query?.includes('account_alias=old-work-account')));
    await view('backups');
    await page.getByRole('button', {name: 'Create encrypted backup'}).click();
    await page.getByLabel('Owner password').fill('A-unique-password-123');
    await page.getByRole('button', {name: 'Create backup', exact: true}).click();
    await page.getByRole('dialog').waitFor({state: 'hidden'});
    await view('settings');
    await page.getByRole('button', {name: 'Save settings'}).click();
    await page.getByText('Settings saved.', {exact: true}).waitFor();
    for (const width of [360, 768, 1365]) {
      await page.setViewportSize({width, height: 900});
      for (const theme of ['light', 'dark']) {
        if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme-toggle').click();
        for (const pageName of ['overview', 'upstreams', 'tools', 'connections', 'profiles', 'clients', 'approvals', 'skills', 'security', 'audit', 'backups', 'settings']) {
          await view(pageName);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${pageName} ${width}px ${theme} overflow`);
        }
      }
      if (width === 360) {
        await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, '200% text size overflow');
        await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
      }
      if (width === 360) {
        await page.getByRole('button', {name: 'Menu', exact: true}).click();
        await page.getByRole('navigation').getByRole('link', {name: 'MCP servers', exact: true}).click();
        await page.getByRole('heading', {name: 'MCP servers', exact: true}).waitFor();
      }
    }
    for (const title of ['Gateway overview', 'MCP servers', 'Tool review', 'Connections', 'Profiles & grants', 'Agent clients', 'One-use approvals', 'Reviewed skills', 'Security', 'Audit events', 'Backups & export', 'Settings & diagnostics']) {
      await page.getByRole('navigation').getByRole('link', {name: title, exact: true}).click();
      await page.getByRole('heading', {name: title, exact: true}).waitFor();
      const refresh = page.getByRole('button', {name: /^(Refresh state|Refresh list|Refresh diagnostics)$/});
      if (await refresh.count()) { await refresh.click(); await page.locator('main[aria-busy="false"]').waitFor(); }
    }
    assert.equal(await page.evaluate(() => Object.keys(localStorage).some(key => /token|secret|password/i.test(key))), false);
    const mutations = calls.filter(call => call.method !== 'GET' && !['/setup/claim', '/auth/session'].includes(call.path));
    assert(mutations.length >= 10);
    assert(mutations.every(call => call.csrf === 'csrf-browser-test'));
    assert.deepEqual(errors, []);
    await page.getByRole('button', {name: 'Log out', exact: true}).click();
    await page.getByRole('heading', {name: 'Owner login'}).waitFor();
  } finally { await browser.close(); }
});
