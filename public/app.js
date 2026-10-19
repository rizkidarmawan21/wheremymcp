const $ = (selector) => document.querySelector(selector);
const main = $('#main');
const dialog = $('#dialog');
const nav = $('#navigation');
let csrf = '';
let authenticated = false;
let mfaEnabled = false;
let viewVersion = 0;
let noticeTimer;
const pages = {
  overview: ['Gateway overview', 'Your gateway state and recent policy decisions.'],
  upstreams: ['MCP servers', 'Register remote servers, discover tools, then explicitly approve the server and its tools.'],
  tools: ['Tool review', 'Auto approve tools from trusted MCP servers in bulk, or review individual tools here. Then choose which tools a client profile can use.'],
  connections: ['Connections', 'Keep account identities and credentials distinct. Tool grants stay bound to stable connection IDs.'],
  profiles: ['Profiles & grants', 'A profile decides which tools an agent client can use. Allow only the tools it needs; everything else stays blocked.'],
  clients: ['Agent clients', 'Issue a separate profile-bound token for each client. Tokens appear only once.'],
  management: ['Management MCP', 'Manage WhereMyMCP from your agent through its built-in MCP endpoint. Separate tokens control read, write and delete access.'],
  approvals: ['One-use approvals', 'Authorize one exact write or delete call. The client, tool and argument object must match.'],
  skills: ['Reviewed skills', 'Import files for inspection. Approval does not execute content or install hooks.'],
  security: ['Security', 'Manage owner MFA and the gateway emergency stop.'],
  audit: ['Audit events', 'Inspect policy decisions without recording tool arguments or results.'],
  backups: ['Backups & export', 'Create encrypted backups and export portable configuration.'],
  settings: ['Settings & diagnostics', 'Inspect runtime checks and update supported instance settings.']
};
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key === 'text') node.textContent = value;
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const p = (text, cls = '') => el('p', {class: cls}, text);
const code = (value) => el('pre', {}, typeof value === 'string' ? value : JSON.stringify(value, null, 2));
function action(label, fn, cls = '', icon = '') {
  const button = el('button', {type: 'button', class: icon ? `icon-btn ${cls}` : cls, 'aria-label': icon ? label : undefined, title: icon ? label : undefined, disabled: typeof fn !== 'function'}, icon ? uiIcon(icon) : label);
  if (typeof fn === 'function') button.addEventListener('click', async () => {
    button.disabled = true; button.setAttribute('aria-busy', 'true');
    try { await run(fn); } finally { button.disabled = false; button.removeAttribute('aria-busy'); }
  });
  return button;
}
const actions = (...nodes) => el('div', {class: 'actions'}, nodes);
const section = (title, ...children) => el('section', {class: 'panel'}, el('h2', {}, title), children);
const details = (title, ...children) => { const open = children.at(-1) === true ? children.pop() : false; return el('details', {open}, el('summary', {}, title), children); };
function descriptionSummary(value) {
  const text = String(value || 'No description supplied.').split(/<(?:examples|hints)>/i)[0].replace(/\s+/g, ' ').trim() || 'See tool details.';
  const sentence = text.match(/^.*?[.!?](?:\s|$)/)?.[0].trim() || text;
  return sentence.length > 240 ? `${sentence.slice(0, 237).replace(/\s+\S*$/, '')}…` : sentence;
}
function toolDescription(value) {
  const text = String(value || 'No description supplied.').trim(), preview = descriptionSummary(text);
  if (preview === text.replace(/\s+/g, ' ')) return p(preview, 'tool-description-preview muted');
  const content = [], blocks = [...text.matchAll(/<(examples|hints)>([\s\S]*?)<\/\1>/gi)];
  let offset = 0;
  for (const block of blocks) {
    const prose = text.slice(offset, block.index).trim();
    if (prose) content.push(p(prose, 'description-prose'));
    content.push(el('section', {class: 'description-section'}, el('h4', {}, block[1].toLowerCase() === 'examples' ? 'Examples' : 'Usage notes'), block[1].toLowerCase() === 'examples' ? code(block[2].trim()) : p(block[2].trim(), 'description-prose')));
    offset = block.index + block[0].length;
  }
  const remaining = text.slice(offset).trim();
  if (remaining) content.push(p(remaining, 'description-prose'));
  return el('div', {class: 'tool-description'}, p(preview, 'tool-description-preview muted'), details(blocks.length ? 'Usage notes & examples' : 'Full description', el('div', {class: 'description-content'}, content)));
}
const time = (value) => value ? new Date(Number(value)).toLocaleString() : 'Never';
const listOf = (result, key) => Array.isArray(result) ? result : result[key] || [];
const idPath = (base, id, suffix = '') => `/api/v1/${base}/${encodeURIComponent(id)}${suffix}`;
function notify(message) {
  clearTimeout(noticeTimer);
  $('#notice').textContent = message;
  $('#notice').hidden = false;
  noticeTimer = setTimeout(() => { $('#notice').hidden = true; }, 6500);
}
async function run(fn) {
  try { await fn(); } catch (error) { notify(error.message || 'The request failed. Try again.'); }
}
async function api(path, method = 'GET', body) {
  const headers = {Accept: 'application/json'};
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (csrf) headers['x-csrf-token'] = csrf;
  }
  let response;
  try { response = await fetch(path, {method, headers, credentials: 'same-origin', body: method === 'GET' ? undefined : JSON.stringify(body ?? {})}); }
  catch { throw new Error('Cannot reach this instance. Check its connection and retry.'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (authenticated && (response.status === 401 || (response.status === 403 && data.message === 'Owner session required'))) {
      authenticated = false; csrf = ''; closeDialog(); shell(false); showLogin();
    }
    const error = new Error(`${data.message || data.error || `Request failed (${response.status})`}${data.request_id ? ` · Request ${data.request_id}` : ''}`);
    error.status = response.status;
    error.retryAfterMs = Math.max(1000, Math.min(60000, (Number(response.headers.get('retry-after')) || 1) * 1000));
    throw error;
  }
  return data;
}
function errorBlock(error, retry) { return section('Could not load this view', el('p', {class: 'error', role: 'alert'}, error.message), action('Retry loading', retry)); }
function empty(message) { return el('div', {class: 'empty'}, p(message)); }
function field(spec) {
  const id = `field-${spec.name}`;
  let input;
  if (spec.type === 'select') {
    input = el('select', {id, name: spec.name, required: spec.required});
    for (const option of spec.options || []) input.append(el('option', {value: typeof option === 'object' ? option.value : option}, typeof option === 'object' ? option.label : option));
  } else if (spec.type === 'textarea' || spec.type === 'json') input = el('textarea', {id, name: spec.name, required: spec.required, rows: spec.rows || 5, spellcheck: 'false'});
  else input = el('input', {id, name: spec.name, type: spec.type || 'text', required: spec.required, min: spec.min, max: spec.max, minlength: spec.minlength, maxlength: spec.maxlength, pattern: spec.pattern, autocomplete: spec.autocomplete || 'off', inputmode: spec.inputmode, step: spec.step, disabled: spec.disabled});
  if (spec.type === 'select' && spec.disabled) input.disabled = true;
  if (spec.type === 'checkbox') input.checked = !!spec.value;
  else if (spec.value !== undefined) input.value = typeof spec.value === 'object' ? JSON.stringify(spec.value, null, 2) : spec.value;
  if (spec.placeholder) input.placeholder = spec.placeholder;
  const hintId = `${id}-hint`;
  if (spec.hint) input.setAttribute('aria-describedby', hintId);
  const label = el('label', {for: id}, spec.label, spec.required ? ' *' : '');
  const control = spec.type === 'checkbox' ? el('label', {class: 'check-label', for: id}, input, spec.label) : input;
  // password fields get a reveal toggle: long generated secrets are approximate at best when masked
  const controlNode = spec.type === 'password' ? el('div', {class: 'pw-row'}, control, revealToggle(input)) : control;
  return el('div', {class: 'field'}, spec.type === 'checkbox' ? controlNode : [label, controlNode], spec.hint ? el('span', {id: hintId, class: 'hint'}, spec.hint) : null);
}
const SVG_NS = 'http://www.w3.org/2000/svg';
const svgShape = (tag, attrs) => { const node = document.createElementNS(SVG_NS, tag); for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value)); return node; };
function eyeIcon(off) {
  const svg = svgShape('svg', {viewBox: '0 0 24 24', width: 20, height: 20, 'aria-hidden': 'true', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.75, 'stroke-linecap': 'round', 'stroke-linejoin': 'round'});
  svg.append(svgShape('path', {d: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z'}), svgShape('circle', {cx: 12, cy: 12, r: 2.75}));
  if (off) svg.append(svgShape('path', {d: 'm4 4 16 16'}));
  return svg;
}
const ICONS = {
  close: [['path', {d: 'M18 6 6 18M6 6l12 12'}]],
  copy: [['rect', {x: 9, y: 9, width: 13, height: 13, rx: 2}], ['path', {d: 'M5 15V5a2 2 0 0 1 2-2h10'}]],
  file: [['path', {d: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Z'}], ['path', {d: 'M14 3v6h6'}]],
  pencil: [['path', {d: 'M12 20h9'}], ['path', {d: 'M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z'}]],
  trash: [['path', {d: 'M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6'}]],
  ban: [['circle', {cx: 12, cy: 12, r: 9}], ['path', {d: 'm5.3 5.3 13.4 13.4'}]],
  check: [['path', {d: 'M4 12.5 9 17.5 20 6.5'}]],
  power: [['path', {d: 'M12 3v9M18.4 6.6a9 9 0 1 1-12.8 0'}]],
  refresh: [['path', {d: 'M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6'}]]
};
function uiIcon(name) {
  const svg = svgShape('svg', {viewBox: '0 0 24 24', width: 18, height: 18, 'aria-hidden': 'true', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.75, 'stroke-linecap': 'round', 'stroke-linejoin': 'round'});
  for (const [tag, attrs] of ICONS[name]) svg.append(svgShape(tag, attrs));
  return svg;
}
function revealToggle(input) {
  const button = el('button', {type: 'button', class: 'reveal-toggle', 'aria-pressed': 'false', 'aria-label': 'Show value'});
  button.append(eyeIcon(false));
  button.addEventListener('click', () => {
    const visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    button.replaceChildren(eyeIcon(visible));
    button.setAttribute('aria-pressed', String(!visible));
    button.setAttribute('aria-label', visible ? 'Hide value' : 'Show value');
    input.focus({preventScroll: true});
  });
  return button;
}
function form(fields, submitLabel, onSubmit) {
  const error = p('', 'error'); error.setAttribute('role', 'alert');
  const submit = el('button', {type: 'submit', class: 'primary'}, submitLabel);
  const node = el('form', {}, fields.map(spec => spec.inDetails ? el('details', {}, el('summary', {}, spec.detailsLabel), field(spec)) : field(spec)), error, actions(submit));
  node.addEventListener('submit', async (event) => {
    event.preventDefault(); error.textContent = ''; submit.disabled = true;
    const data = {};
    try {
      for (const spec of fields) {
        const input = node.elements.namedItem(spec.name);
        if (spec.type === 'checkbox') data[spec.name] = input.checked;
        else if (spec.type === 'number') { if (input.value !== '') data[spec.name] = Number(input.value); }
        else if (spec.type === 'json') { if (input.value.trim()) data[spec.name] = JSON.parse(input.value); }
        else if (input.value !== '') data[spec.name] = input.value;
      }
      await onSubmit(data, node);
    } catch (err) { error.textContent = err instanceof SyntaxError ? 'Enter valid JSON. Check quotes, commas and braces.' : err.message; error.scrollIntoView({block: 'nearest'}); }
    finally { submit.disabled = false; }
  });
  return node;
}
function closeDialog() { if (dialog.open) dialog.close(); dialog.replaceChildren(); dialog.classList.remove('grants-dialog'); }
function modal(title, ...children) {
  closeDialog();
  dialog.append(el('div', {class: 'dialog-head'}, el('h2', {id: 'dialog-title'}, title), action('Close', closeDialog, '', 'close')), el('div', {class: 'dialog-body'}, ...children.flat(Infinity).filter(child => child !== null && child !== undefined)));
  dialog.showModal();
}
function formModal(title, fields, label, fn, intro) {
  modal(title, intro ? p(intro, 'muted') : null, form(fields, label, async data => {
    const result = await fn(data); closeDialog();
    if (result?.reauthenticate) { authenticated = false; csrf = ''; showLogin(); notify('Saved. Log in again with your current credentials.'); }
    else { await route(); notify(`${title} completed.`); }
  }));
}
async function confirmAction(title, message, fn, label = 'Confirm', refresh = true) {
  modal(title, p(message), actions(action('Cancel', closeDialog), action(label, async () => {
    const initialContent = dialog.firstElementChild;
    await fn();
    if (dialog.firstElementChild === initialContent) closeDialog();
    if (refresh) { await route(); notify(`${title} completed.`); }
  }, 'danger')));
}
async function copy(text) {
  if (!navigator.clipboard) throw new Error('Clipboard unavailable. Select and copy the displayed text manually.');
  await navigator.clipboard.writeText(text); notify('Copied to clipboard.');
}
function revealToken(title, token, message, onSaved) {
  const url = new URL('/mcp', location.href).href;
  const blocks = [
    ['Codex CLI', 'Codex CLI \u2014 save to ~/.codex/config.toml, then set WHEREMYMCP_TOKEN in your shell environment', `[mcp_servers.wheremymcp]\nurl = "${url}"\nbearer_token_env_var = "WHEREMYMCP_TOKEN"`],
    ['Claude Code', 'Claude Code \u2014 add to .mcp.json; set WHEREMYMCP_TOKEN in the client environment', JSON.stringify({mcpServers: {wheremymcp: {type: 'http', url, headers: {Authorization: 'Bearer ${WHEREMYMCP_TOKEN}'}}}}, null, 2)],
    ['Cursor', 'Cursor \u2014 add to ~/.cursor/mcp.json; set WHEREMYMCP_TOKEN in the client environment', JSON.stringify({mcpServers: {wheremymcp: {url, headers: {Authorization: 'Bearer ${env:WHEREMYMCP_TOKEN}'}}}}, null, 2)],
    ['Gemini CLI', 'Gemini CLI \u2014 add to settings.json mcpServers; set WHEREMYMCP_TOKEN in the client environment', JSON.stringify({mcpServers: {wheremymcp: {httpUrl: url, headers: {Authorization: 'Bearer ${WHEREMYMCP_TOKEN}'}}}}, null, 2)]
  ];
  modal(title, p(message), code(token), actions(action('Copy token', () => copy(token), '', 'copy')), p('Copy a config block into your agent, then add the token separately to its environment as WHEREMYMCP_TOKEN. Config blocks contain no credential. The token is shown once.', 'hint'), ...blocks.map(([agent, name, text]) => details(name, code(text), actions(action(`Copy ${agent} config`, () => copy(text), '', 'copy')))), action('I saved it', async () => { closeDialog(); if (onSaved) { try { await onSaved(); } catch (err) { notify(`Saved token. Refresh failed: ${err.message}`); } } }, 'primary'));
}
function reveal(title, value, message) {
  modal(title, p(message), code(value), actions(action('Copy', () => copy(value), '', 'copy'), action('I saved it', closeDialog, 'primary')));
}
function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const link = el('a', {href: url, download: filename}); document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function jsonDownload(filename, data) { downloadBlob(filename, new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'})); }
async function downloadBackup(name, body) {
  const response = await fetch(`${idPath('backups', name)}/download`, {method: 'POST', headers: {'content-type': 'application/json', 'x-csrf-token': csrf, Accept: 'application/octet-stream'}, credentials: 'same-origin', body: JSON.stringify(body)});
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `Backup download failed (${response.status}).`);
  }
  downloadBlob(name, await response.blob());
}
function importConfig() {
  const importForm = form([{name: 'config', label: 'Exported configuration (JSON)', type: 'json', required: true, placeholder: '{ "version": 2, "profiles": [ ... ] }', hint: 'Paste an export or read a JSON file. Preview does not change this instance.'}, {name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}, {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.', placeholder: '6-digit code'}], 'Preview config import', async data => {
    if (!data.config || typeof data.config !== 'object' || Array.isArray(data.config)) throw new Error('Configuration must be a JSON export object.');
    modal('Review configuration import', p('Import configuration only after reviewing all server URLs, account bindings and policy grants. Imported connections require reauthentication and imported tools require review again. Owner credentials, sessions and client tokens are not imported.'), details('Inspect complete configuration', code(data.config)), actions(action('Cancel', closeDialog), action('Import reviewed configuration', async () => {
      const result = await api('/api/v1/config/import', 'POST', data);
      await route(); modal('Configuration import result', p('Check account credentials, refresh server discovery and approve tools before issuing new client tokens.'), code(result), action('Done', closeDialog));
    }, 'primary')));
  });
  const file = field({name: 'import_file', label: 'Read export JSON file', type: 'file'});
  file.querySelector('input').accept = '.json,application/json';
  file.querySelector('input').addEventListener('change', event => run(async () => {
    const selected = event.currentTarget.files?.[0];
    if (!selected) return;
    if (selected.size > 1024 * 1024) throw new Error('Choose an export no larger than 1 MiB.');
    importForm.elements.namedItem('config').value = await selected.text();
  }));
  modal('Import configuration', p('This operation imports portable configuration. Create an encrypted backup first if this instance already contains data.', 'hint'), file, importForm);
}
function shell(active) {
  $('#shell').classList.toggle('has-session', active);
  $('#logout').hidden = !active; $('#menu-toggle').hidden = !active; $('#emergency-stop').hidden = !active;
  nav.hidden = !active || window.innerWidth < 928;
  $('#menu-toggle').setAttribute('aria-expanded', String(!nav.hidden));
}
function initNav() {
  nav.replaceChildren();
  for (const [label, keys] of [['Workspace', ['overview']], ['Registry', ['upstreams', 'connections', 'tools', 'skills']], ['Access', ['profiles', 'clients', 'management', 'approvals']], ['Operations', ['security', 'audit', 'backups', 'settings']]]) {
    nav.append(p(label, 'nav-caption'));
    for (const key of keys) nav.append(el('a', {href: `#${key}`, 'data-page': key}, pages[key][0]));
  }
}
function summaryRow(title, status, meta = [], ...buttons) {
  return el('article', {class: 'panel'}, el('div', {class: 'row-head'}, el('div', {}, el('h2', {class: 'row-title'}, title), status ? el('span', {class: `status ${/pending|drift|quarant|revoked|disabled|error/.test(status) ? 'warning' : ''}`}, status) : null), actions(buttons)), el('div', {class: 'metadata'}, meta.filter(Boolean).map(text => el('span', {}, text))));
}
async function boot() {
  main.setAttribute('aria-busy', 'true');
  try {
    const [setup, session] = await Promise.all([api('/api/v1/setup'), api('/auth/session')]);
    mfaEnabled = !!session.mfa_enabled;
    if (!setup.claimed) showSetup(setup);
    else if (!session.authenticated) showLogin();
    else { authenticated = true; csrf = session.csrf_token || ''; shell(true); await route(); }
  } catch (error) { main.replaceChildren(errorBlock(error, boot)); }
  finally { main.setAttribute('aria-busy', 'false'); }
}
function authPanel(title, description, ...children) {
  main.replaceChildren(el('div', {class: 'auth'}, el('h1', {}, title), p(description, 'muted'), el('section', {class: 'panel'}, children)));
  shell(false);
}
function showSetup(setup) {
  authPanel('Claim this instance', 'Create the single owner account using the one-time bootstrap token. Read it from the protected file inside the container (docker: docker compose exec hub cat /secrets/bootstrap.token), then enter it below. The token expires and cannot be reused.',
    setup.public_mode ? p('Public mode requires owner MFA before gateway use. Configure MFA immediately after login.', 'hint') : null,
    form([{name: 'setup_token', label: 'Setup token', type: 'password', required: true, hint: 'Stored at /secrets/bootstrap.token (mode 0600). Reads once, then claim it before it expires.', placeholder: 'One-time token from instance bootstrap or the CLI'}, {name: 'password', label: 'Owner password', type: 'password', required: true, minlength: 8, maxlength: 256, autocomplete: 'new-password', hint: 'Minimum 8 characters with lowercase, uppercase, a number and a symbol.', placeholder: 'e.g. Kopi-susu-8!'}], 'Create owner account', async data => {
      const result = await api('/setup/claim', 'POST', data);
      showLogin(); reveal('Save your recovery codes', (result.recovery_codes || []).join('\n'), 'These codes appear only once. Store them offline. Each code can be used once if MFA is unavailable.');
    }));
}
function showLogin() {
  const fields = mfaEnabled ? [
    {name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'},
    {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '6-digit code'},
    {name: 'recovery_code', label: 'Recovery code', type: 'password', inDetails: true, detailsLabel: 'Authenticator unavailable? Use a recovery code instead', placeholder: 'xxxxx-xxxxx (one unused code)'}
  ] : [{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}];
  authPanel('Owner login', 'Manage server approvals, credentials and client access for this instance.',
    form(fields, 'Log in', async data => {
      const result = await api('/auth/session', 'POST', data);
      csrf = result.csrf_token || ''; authenticated = true;
      const session = await api('/auth/session'); mfaEnabled = !!session.mfa_enabled; csrf = session.csrf_token || csrf;
      shell(true); await route();
    }));
}

async function route() {
  if (!authenticated) return;
  const version = ++viewVersion;
  const key = location.hash.slice(1) || 'overview';
  const page = pages[key] ? key : 'overview';
  for (const link of nav.querySelectorAll('a')) {
    if (link.dataset.page === page) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  }
  document.title = `${pages[page][0]} · WhereMyMCP`;
  main.replaceChildren(el('p', {role: 'status'}, `Loading ${pages[page][0].toLowerCase()}…`)); main.setAttribute('aria-busy', 'true');
  if (window.innerWidth < 928) { nav.hidden = true; $('#menu-toggle').setAttribute('aria-expanded', 'false'); }
  const target = el('div');
  try {
    await renderers[page](target);
    if (version === viewVersion && authenticated) { main.replaceChildren(...target.childNodes); main.focus({preventScroll: true}); }
  } catch (error) { if (version === viewVersion && authenticated) main.replaceChildren(errorBlock(error, route)); }
  finally { if (version === viewVersion) main.setAttribute('aria-busy', 'false'); }
}
function heading(target, key, ...buttons) {
  const [title, description] = pages[key];
  target.append(el('div', {class: 'page-head'}, el('div', {}, el('h1', {}, title), p(description)), actions(buttons)));
}
function eventsView(events, compact = false) {
  if (compact && events.length) return el('div', {}, events.slice(0, 6).map(event => el('article', {class: 'audit-entry'}, el('div', {class: 'row-head'}, el('strong', {}, event.action || 'Event'), el('span', {class: 'status'}, event.outcome === 'ok' ? 'Recorded' : event.outcome || 'Recorded')), p(`${time(event.ts)} · ${event.account_alias || (event.principal === 'owner' ? 'Owner' : event.principal === 'system' ? 'System' : 'Agent client')}`, 'hint'))));
  return events.length ? el('div', {}, events.map(event => el('article', {class: 'audit-entry'}, el('div', {class: 'row-head'}, el('strong', {}, event.action || 'Event'), el('span', {class: 'status'}, event.outcome || 'Recorded')), p(`${time(event.ts)} · ${event.principal || 'System'}${event.resource ? ` · ${event.resource}` : ''}`, 'hint'), event.profile_id || event.account_id || event.account_alias ? el('div', {class: 'metadata'}, event.profile_id ? el('span', {}, `Profile: ${event.profile_id}`) : null, event.account_alias ? el('span', {}, `Account at event: ${event.account_alias}`) : null, event.account_id ? el('span', {}, `Account ID: ${event.account_id}`) : null) : null, event.detail ? p(event.detail, 'hint') : null))) : empty('No audit events match this view. Actions on this instance will appear here.');
}
// first-run path through the workspace, computed only from real registry counts
function gettingStarted(counts) {
  const n = key => Number(counts[key] || 0);
  const steps = [
    ['Register an MCP server', '#upstreams', n('upstreams') > 0, 'Add its MCP URL. Select an account only if that server needs credentials.'],
    ['Enable its tools', '#upstreams', n('enabled_tools') > 0, 'Use Auto approve tools for servers you trust. Select multiple servers to handle them together; manual Tool review is optional.'],
    ['Choose access in Default', '#profiles', n('grants') > 0, 'Open Default, choose tools by MCP server or Select all available, then Save access. No new profile is required.'],
    ['Issue a client token', '#clients', n('active_clients') > 0, 'Choose Default, save the token and copy the configuration into your agent application.']
  ];
  if (steps.every(step => step[2])) return null;
  return section('Getting started', p('The order below is the shortest path to your first successful client tool call. Steps marked Done are based on this instance\'s real state.', 'hint'), el('ol', {class: 'steps'}, steps.map(([label, hash, done, hint], index) => {
    const remaining = steps.filter(step => !step[2]);
    const next = remaining[0] === steps[index];
    return el('li', {class: `step ${done ? 'step-done' : ''}`}, el('span', {class: 'state'}, done ? 'Done' : next ? 'Next' : 'Waiting'), el('a', {href: hash}, label), p(hint, 'hint'));
  })));
}
function registryInventory(counts) {
  const entries = [
    ['upstreams', 'upstreams', 'MCP servers', 'Remote endpoints'],
    ['connections', 'connections', 'Connections', 'Account credentials'],
    ['tools', 'tools', 'Tools', 'Discovered capabilities'],
    ['profiles', 'profiles', 'Profiles', 'Client access policies'],
    ['clients', 'clients', 'Agent clients', 'Issued client identities'],
    ['skills', 'skills', 'Skills', 'Imported skill files']
  ];
  return section('Registry inventory', el('div', {class: 'registry-list'}, entries.map(([countKey, page, label, description]) => el('a', {href: `#${page}`, class: 'registry-link'}, el('div', {}, el('span', {class: 'registry-label'}, label), el('span', {class: 'registry-description'}, description)), el('span', {class: 'registry-count'}, Number(counts[countKey] || 0))))));
}
async function stopControl(enabled) {
  await confirmAction(enabled ? 'Stop gateway calls' : 'Resume gateway calls', enabled ? 'Deny all agent tool calls immediately. Owner access stays available so you can inspect and repair policy.' : 'Allow agent calls again under the current grants, approvals and connection policy.', () => api('/api/v1/emergency-stop', 'POST', {enabled}), enabled ? 'Stop all calls' : 'Resume calls');
}
async function autoApproveServers(servers) {
  if (!servers.length) { notify('Select at least one MCP server.'); return; }
  const progress = p('', 'hint'); progress.setAttribute('role', 'status');
  modal('Auto approve tools', p(`Trust ${servers.length === 1 ? servers[0].name : `${servers.length} selected MCP servers`} and enable their currently advertised tools. This refreshes discovery, approves the servers and replaces tool classifications using their metadata.`), p('Read-only hint: Read. Destructive hint: Delete. Missing or unclear hints: Write. Write/delete calls still require one-use approval. Future metadata changes remain quarantined.', 'hint'), form([{name: 'trust_server', label: 'I trust the selected servers to describe their tools', type: 'checkbox', required: true}], 'Auto approve tools', async data => {
    const results = []; let next = 0, completed = 0;
    progress.textContent = `Processing 0 of ${servers.length} servers…`;
    await Promise.all(Array.from({length: Math.min(4, servers.length)}, async () => {
      while (next < servers.length) {
        const server = servers[next++];
        try {
          let result;
          try { result = await api(idPath('upstreams', server.id, '/auto-approve-tools'), 'POST', data); }
          catch (error) {
            if (error.status !== 429) throw error;
            progress.textContent = `Rate limit reached. Waiting ${Math.ceil(error.retryAfterMs / 1000)} seconds, then continuing (${completed} of ${servers.length} complete).`;
            await new Promise(resolve => setTimeout(resolve, error.retryAfterMs));
            result = await api(idPath('upstreams', server.id, '/auto-approve-tools'), 'POST', data);
          }
          results.push({server, result});
        } catch (error) { results.push({server, error: error.message}); }
        completed++; progress.textContent = `Processed ${completed} of ${servers.length} servers.`;
      }
    }));
    if (!authenticated) return;
    const failed = results.filter(item => item.error), enabled = results.reduce((sum, item) => sum + (item.result?.approved || 0), 0);
    await route();
    modal(failed.length && !enabled ? 'Tool approval needs attention' : 'Tool approval results', p(`Enabled ${enabled} tools across ${servers.length - failed.length} servers.`), failed.length ? section('Servers needing attention', failed.map(item => p(`${item.server.name}: ${item.error}`, 'error'))) : null, p(enabled ? 'Next: open Default in Profiles & grants, select tools by server or Select all available, then Save access.' : 'Resolve the server errors above, then retry Auto approve tools. No new tool access was granted.', 'hint'), actions(failed.length ? action('Review connections', () => { closeDialog(); location.hash = 'connections'; }) : null, enabled ? action('Choose client tool access', () => { closeDialog(); location.hash = 'profiles'; }) : null, action('Done', closeDialog)));
  }), progress);
}
function reviewTool(tool) {
  formModal(`Enable tool: ${tool.name}`, [{name: 'risk', label: 'Tool behavior', type: 'select', required: true, value: ['read', 'write', 'delete'].includes(tool.risk) ? tool.risk : '', options: [{value: '', label: 'Choose what this tool can do'}, {value: 'read', label: 'Read only: search, list or view data'}, {value: 'write', label: 'Write: create, edit, send or run'}, {value: 'delete', label: 'Delete: remove data'}]}], 'Enable tool', data => api(idPath('tools', tool.id, '/approve'), 'POST', {...data, enabled: true}), 'Choose based on what this tool actually does. Read runs without per-call approval; Write and Delete require one-use approval. Enabling makes the tool available for profile selection.');
}
async function editGrants(profileRow, tools, connections) {
  const profile = await api(idPath('profiles', profileRow.id));
  const grants = new Map((profile.grants || profile.profile?.grants || []).map(grant => [grant.tool_id, grant]));
  const accounts = new Map(connections.map(connection => [connection.id, connection.alias]));
  const selected = new Map(), entries = [], groups = new Map();
  const singleServer = new Set(tools.map(tool => tool.upstream_id)).size === 1;
  const count = p('', 'hint'); count.setAttribute('aria-live', 'polite');
  const error = p('', 'error'); error.setAttribute('role', 'alert');
  const search = el('input', {type: 'search', placeholder: 'Search tools, servers or accounts', 'aria-label': 'Search tools'});
  const list = el('div', {class: 'grant-list'}), noMatches = empty('No tools match this search.'); noMatches.hidden = true;
  const updateCount = () => {
    count.textContent = `${selected.size} tools selected. Save to apply.`;
    for (const group of groups.values()) {
      const chosen = group.entries.filter(item => item.checkbox.checked).length;
      const available = group.entries.filter(item => item.available);
      group.checkbox.checked = available.length ? available.every(item => item.checkbox.checked) : chosen > 0;
      group.checkbox.indeterminate = chosen > 0 && !group.checkbox.checked;
      group.checkbox.disabled = !group.entries.some(item => item.available || item.checkbox.checked);
      group.summary.textContent = `Show ${group.entries.length} tools (${chosen} selected)`;
    }
  };
  for (const tool of [...tools].sort((a, b) => String(a.upstream_name || '').localeCompare(String(b.upstream_name || '')) || String(a.name).localeCompare(String(b.name)))) {
    const existing = grants.get(tool.id);
    const retained = existing && existing.action_class === tool.risk && (existing.connection_id || null) === (tool.connection_id || null);
    const available = !!tool.enabled && ['read', 'write', 'delete'].includes(tool.risk) && (!tool.upstream_status || tool.upstream_status === 'active') && tool.approved_fingerprint === tool.fingerprint;
    const name = tool.name || 'Unnamed tool', account = accounts.get(tool.connection_id) || (tool.connection_id ? 'Account unavailable' : 'No account required');
    const checkbox = el('input', {type: 'checkbox', 'aria-label': `Allow ${name}`, disabled: !available && !retained, 'aria-describedby': `grant-info-${tool.id}`}); checkbox.checked = !!retained;
    if (retained) selected.set(tool.id, tool);
    const reason = !available ? 'Not enabled yet. Use Auto approve tools in MCP servers, or review this tool manually.' : tool.risk === 'read' ? 'Can view data.' : 'Can change data. Each call also needs your one-use approval.';
    const info = el('div', {class: 'grant-copy', id: `grant-info-${tool.id}`}, el('strong', {}, name), p(descriptionSummary(tool.description), 'grant-description'), p(`${account} · ${reason}`, 'hint'), existing && !retained ? p('Previous access no longer matches this tool or account. Saving removes that outdated grant.', 'error') : null);
    const entry = el('div', {class: 'grant-entry'}, el('label', {class: 'grant-toggle'}, checkbox, info), el('span', {class: 'status'}, {read: 'Read only', write: 'Write', delete: 'Delete'}[tool.risk] || 'Needs review'));
    checkbox.addEventListener('change', () => { if (checkbox.checked) selected.set(tool.id, tool); else selected.delete(tool.id); updateCount(); });
    const groupKey = tool.upstream_id || tool.upstream_name || 'unknown';
    if (!groups.has(groupKey)) {
      const serverName = tool.upstream_name || 'MCP server', groupCheck = el('input', {type: 'checkbox', 'aria-label': `Allow all tools from ${serverName}`}), summary = el('summary'), content = el('div');
      const disclosure = el('details', {open: singleServer}, summary, content);
      const group = {node: el('section', {class: 'grant-group'}, el('label', {class: 'check-label grant-server'}, groupCheck, el('strong', {}, serverName)), disclosure), content, checkbox: groupCheck, disclosure, summary, entries: []};
      groupCheck.addEventListener('change', () => {
        for (const item of group.entries) { if (!groupCheck.checked || item.available) { item.checkbox.checked = groupCheck.checked; if (groupCheck.checked) selected.set(item.tool.id, item.tool); else selected.delete(item.tool.id); } }
        updateCount();
      });
      groups.set(groupKey, group); list.append(group.node);
    }
    const group = groups.get(groupKey), item = {entry, checkbox, group, available, tool, text: `${name} ${tool.description || ''} ${tool.upstream_name || ''} ${account}`.toLowerCase()};
    group.content.append(entry); group.entries.push(item); entries.push(item);
  }
  search.addEventListener('input', () => {
    const query = search.value.toLowerCase().trim();
    for (const item of entries) item.entry.hidden = !item.text.includes(query);
    for (const group of groups.values()) { group.node.hidden = !group.entries.some(item => !item.entry.hidden); group.disclosure.open = !!query || singleServer; }
    noMatches.hidden = entries.some(item => !item.entry.hidden);
  });
  updateCount();
  const selectAll = action('Select all available', () => { for (const item of entries) if (item.available) { item.checkbox.checked = true; selected.set(item.tool.id, item.tool); } updateCount(); }); selectAll.disabled = !entries.some(item => item.available);
  const clear = action('Clear selection', () => { selected.clear(); for (const item of entries) item.checkbox.checked = false; updateCount(); });
  const save = action('Save access', async () => {
    error.textContent = '';
    if (selected.size > 5000) { error.textContent = 'A profile can contain up to 5000 tools. Choose fewer servers or tools.'; return; }
    try { await api(idPath('profiles', profileRow.id, '/grants'), 'PUT', {grants: [...selected.values()].map(tool => ({tool_id: tool.id, connection_id: tool.connection_id || null, action_class: tool.risk}))}); closeDialog(); await route(); notify('Tool access saved. Client permissions updated.'); }
    catch (err) { error.textContent = err.message; }
  }, 'primary');
  const locked = entries.filter(item => !item.available).length;
  modal(`Tool access: ${profileRow.name}`, p('Choose entire MCP servers below, or Select all available. Expand a server only when you want to pick individual tools. Changes apply when you save.', 'hint'), locked ? el('div', {class: 'access-help'}, p(`${locked} tools are not enabled yet. Auto approve them in MCP servers, then return here.`), action('Enable server tools', () => { closeDialog(); location.hash = 'upstreams'; })) : null, tools.length ? el('div', {class: 'grant-search'}, search, selectAll, clear) : null, tools.length ? list : empty('No tools discovered yet. Add an MCP server first.'), noMatches);
  dialog.classList.add('grants-dialog');
  dialog.append(el('div', {class: 'dialog-footer'}, count, error, actions(action('Cancel', closeDialog), save)));
}
const renderers = {
  async overview(target) {
    const result = await api('/api/v1/overview');
    heading(target, 'overview', action('Refresh state', route, '', 'refresh'));
    target.append(el('section', {class: `banner ${result.emergency_stop ? 'stopped' : ''}`}, el('div', {}, el('h2', {}, result.emergency_stop ? 'Gateway calls are stopped' : 'Gateway policy is active'), p(result.emergency_stop ? 'All agent tool calls are denied until you resume the gateway.' : 'Clients can invoke only approved tools with matching profile grants.')), action(result.emergency_stop ? 'Resume gateway calls' : 'Emergency stop', () => stopControl(!result.emergency_stop), result.emergency_stop ? '' : 'danger')));
    const counts = result.counts || {};
    const onboarding = gettingStarted(counts);
    if (onboarding) target.append(onboarding);
    target.append(el('div', {class: 'overview-workspace'}, registryInventory(counts), section('Recent policy decisions', p('Latest recorded actions on this gateway.', 'hint'), eventsView(result.recent_events || [], true), el('a', {href: '#audit', class: 'panel-link'}, 'View audit events'))));
    if (!mfaEnabled) target.append(p('Owner MFA is not enabled. Set up MFA in Security before enabling public mode.', 'hint'));
  },
  async upstreams(target) {
    const [result, connections] = await Promise.all([api('/api/v1/upstreams'), api('/api/v1/connections')]);
    const add = () => formModal('Register MCP server', [
      {name: 'name', label: 'Server name', required: true, placeholder: 'e.g. docs-server'}, {name: 'url', label: 'Remote MCP URL', type: 'url', required: true, placeholder: 'https://example.com/mcp'},
      {name: 'connection_id', label: 'Account connection', type: 'select', options: [{value: '', label: 'No credentials'}, ...listOf(connections, 'connections').filter(c => ['active', 'connected'].includes(c.status)).map(c => ({value: c.id, label: `${c.alias} (${c.provider}${c.identity ? `, ${c.identity}` : ''})`}))], hint: 'Only connected accounts can be bound. Finish OAuth consent in Connections first.'},
      {name: 'allowed_private_ips', label: 'Explicit local IP allowlist (JSON array)', type: 'json', value: [], placeholder: '["127.0.0.1"]', hint: 'Only exact IP addresses for a deliberately trusted local server. No CIDRs, wildcards or metadata service IPs.'},
      {name: 'timeout_ms', label: 'Request timeout (milliseconds)', type: 'number', min: 100, max: 60000, value: 15000}
    ], 'Register server', data => {
      if (!Array.isArray(data.allowed_private_ips) || data.allowed_private_ips.some(ip => typeof ip !== 'string' || /[/*]/.test(ip))) throw new Error('Local exceptions must be a JSON array of exact IP address strings.');
      return api('/api/v1/upstreams', 'POST', data);
    }, 'A registered server is pending review. Refresh discovery and approve tools before granting them to clients.');
    heading(target, 'upstreams', action('Register server', add, 'primary'), action('Refresh list', route, '', 'refresh'));
    const rows = listOf(result, 'upstreams');
    if (!rows.length) target.append(empty('No MCP servers registered. Register a remote MCP endpoint to discover its tools.'));
    const selected = new Map(), checkboxes = [];
    const all = el('input', {type: 'checkbox', 'aria-label': 'Select all servers'}), selection = p('0 servers selected.', 'hint');
    const approveSelected = action('Auto approve selected servers', () => autoApproveServers([...selected.values()])); approveSelected.disabled = true;
    const updateSelection = () => { all.checked = selected.size === rows.length && rows.length > 0; all.indeterminate = selected.size > 0 && selected.size < rows.length; approveSelected.disabled = selected.size === 0; selection.textContent = `${selected.size} servers selected.`; };
    all.addEventListener('change', () => { for (const item of checkboxes) { item.checkbox.checked = all.checked; if (all.checked) selected.set(item.row.id, item.row); else selected.delete(item.row.id); } updateSelection(); });
    if (rows.length) target.append(el('div', {class: 'bulk-toolbar'}, el('label', {class: 'check-label'}, all, 'Select all servers'), selection, approveSelected, el('a', {href: '#profiles'}, 'Next: choose client tool access')));
    for (const row of rows) {
      const connection = listOf(connections, 'connections').find(c => c.id === row.connection_id);
      const item = summaryRow(row.name, row.status, [row.url, connection ? `Account: ${connection.alias}` : 'No account credentials', `Timeout: ${row.timeout_ms} ms`],
        action('Refresh tools', async () => { await api(idPath('upstreams', row.id, '/refresh'), 'POST'); await route(); notify('Discovery refreshed. Auto approve trusted tools or review them individually.'); }),
        action('Edit server', () => formModal('Edit MCP server', [
          {name: 'name', label: 'Server name', required: true, value: row.name},
          {name: 'url', label: 'Remote MCP URL', type: 'url', required: true, value: row.url, hint: 'Changing the URL requires a Discovery refresh; then re-approve the tools.'},
          {name: 'connection_id', label: 'Account connection', type: 'select', value: row.connection_id || '', options: [{value: '', label: 'No credentials'}, ...listOf(connections, 'connections').filter(c => ['active', 'connected'].includes(c.status)).map(c => ({value: c.id, label: `${c.alias} (${c.provider})`}))]},
          {name: 'allowed_private_ips', label: 'Explicit local IP allowlist (JSON array)', type: 'json', value: row.allowed_private_ips, placeholder: '["127.0.0.1"]', hint: 'Only exact IP addresses for a deliberately trusted local server.'},
          {name: 'timeout_ms', label: 'Request timeout (milliseconds)', type: 'number', min: 100, max: 60000, value: row.timeout_ms}
        ], 'Save server', data => {
          if (data.allowed_private_ips !== undefined && (!Array.isArray(data.allowed_private_ips) || data.allowed_private_ips.some(ip => typeof ip !== 'string' || /[/*]/.test(String(ip))))) throw new Error('Local exceptions must be a JSON array of exact IP address strings.');
          return api(idPath('upstreams', row.id), 'PATCH', data);
        }), '', 'pencil'),
        action('Approve server', row.status === 'active' ? null : () => confirmAction('Approve server', 'Approve this upstream for routing. Each tool still needs explicit risk review and a profile grant.', () => api(idPath('upstreams', row.id, '/approve'), 'POST'), 'Approve server')),
        action('Disable', row.status === 'active' ? () => confirmAction('Disable server', 'Client tool calls to this server will be denied.', () => api(idPath('upstreams', row.id, '/disable'), 'POST'), 'Disable server') : null, 'danger', 'power'),
        action('Delete', () => confirmAction('Delete server', 'Deletes this server permanently, including all of its discovered tools, profile grants and pending approvals for those tools.', () => api(idPath('upstreams', row.id), 'DELETE'), 'Delete server'), 'danger', 'trash'));
      const checkbox = el('input', {type: 'checkbox', 'aria-label': `Select server ${row.name}`});
      checkbox.addEventListener('change', () => { if (checkbox.checked) selected.set(row.id, row); else selected.delete(row.id); updateSelection(); });
      checkboxes.push({row, checkbox}); const title = item.querySelector('.row-head > div'); title.classList.add('server-select-title'); title.prepend(checkbox);
      item.querySelector('.actions').prepend(action('Auto approve tools', () => autoApproveServers([row])));
      if (row.allowed_private_ips?.length) item.append(p(`Explicit local addresses: ${row.allowed_private_ips.join(', ')}`, 'hint'));
      target.append(item);
    }
  },
  async tools(target) {
    const result = await api('/api/v1/tools');
    heading(target, 'tools', el('a', {href: '#upstreams'}, 'Auto approve MCP servers'), el('a', {href: '#profiles'}, 'Next: choose tool access'), action('Refresh list', route, '', 'refresh'));
    const allRows = listOf(result, 'tools');
    if (!allRows.length) { target.append(empty('No discovered tools. Register a server and use Auto approve tools to get started.')); return; }
    const search = el('input', {type: 'search', 'aria-label': 'Search tools', placeholder: 'Search tool names or descriptions'});
    const servers = el('select', {'aria-label': 'Filter tools by server'}, el('option', {value: ''}, 'All MCP servers'), [...new Map(allRows.map(tool => [tool.upstream_id, tool.upstream_name || 'MCP server']))].map(([id, name]) => el('option', {value: id}, name)));
    const results = el('div'), count = p('', 'hint'); count.setAttribute('role', 'status'); let visible = 50;
    const more = action('Show 50 more tools', () => { visible += 50; render(); });
    function render() {
      const query = search.value.toLowerCase().trim();
      const matching = allRows.filter(tool => (!servers.value || tool.upstream_id === servers.value) && `${tool.name} ${tool.description || ''}`.toLowerCase().includes(query));
      results.replaceChildren(); count.textContent = `Showing ${Math.min(visible, matching.length)} of ${matching.length} tools.`; more.hidden = matching.length <= visible;
      if (!matching.length) results.append(empty('No tools match these filters.'));
      for (const row of matching.slice(0, visible)) {
      const drifted = row.approved_fingerprint && row.fingerprint !== row.approved_fingerprint;
      const status = drifted ? 'Metadata drift: quarantined' : row.enabled ? `Approved ${row.risk}` : row.upstream_status === 'disabled' ? 'Upstream disabled' : 'Pending review';
      const item = summaryRow(row.name || 'Unnamed tool', status, [`Server: ${row.upstream_name || 'MCP server'}`, row.upstream_status && row.upstream_status !== 'active' ? `Server state: ${row.upstream_status}` : ''], action('Review tool', () => reviewTool(row)), row.enabled ? action('Disable tool', () => confirmAction('Disable tool', 'Clients lose access to this tool until it is enabled again.', () => api(idPath('tools', row.id, '/approve'), 'POST', {risk: row.risk, enabled: false}), 'Disable tool'), 'danger') : null);
      item.append(toolDescription(row.description), details('Current schema, annotations & fingerprint', p('Gateway identifier', 'hint'), code(row.gateway_name), p(`Current fingerprint: ${row.fingerprint || 'Unavailable'}`, 'mono'), p(`Approved fingerprint: ${row.approved_fingerprint || 'Not approved'}`, 'mono'), code({input_schema: row.input_schema, annotations: row.annotations})));
      if (drifted) {
        const previous = typeof row.previous_metadata === 'string' ? JSON.parse(row.previous_metadata) : row.previous_metadata;
        item.append(section('Metadata changed since approval', p('Calls remain quarantined until the current metadata is explicitly approved.'), previous ? el('div', {class: 'split'}, el('div', {}, el('h3', {}, 'Previously approved'), code(previous)), el('div', {}, el('h3', {}, 'Current discovery'), code({description: row.description, input_schema: row.input_schema, annotations: row.annotations, fingerprint: row.fingerprint}))) : p('The previous schema snapshot is unavailable. Compare the approved and current fingerprints above, then inspect the current metadata before approving.')));
      }
      results.append(item);
      }
    }
    for (const input of [search, servers]) input.addEventListener('input', () => { visible = 50; render(); });
    target.append(el('div', {class: 'toolbar'}, search, servers), count, results, more); render();
  },
  async connections(target) {
    const result = await api('/api/v1/connections');
    const create = () => formModal('Add account connection', [
      {name: 'provider', label: 'Credential provider', type: 'select', options: ['bearer', 'api_key', 'google', 'github', 'slack', {value: 'remote_oauth', label: 'OAuth remote MCP'}]}, {name: 'alias', label: 'Account alias', required: true, pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', maxlength: 80, placeholder: 'e.g. work-google-drive', hint: 'Use letters, digits, dots, underscores or hyphens; no spaces. Choose a distinct alias for each account.'}, {name: 'identity', label: 'Account identity', placeholder: 'e.g. you@company.com (shown in audit events)'},
      {name: 'secret', label: 'Token / API key / OAuth client secret', type: 'password', placeholder: 'Paste the access token, API key or OAuth client secret', hint: 'Native OAuth uses your BYO client secret and config.client_id. A remote OAuth public client may leave the secret empty. Otherwise supply an access token or API key.'}, {name: 'scopes', label: 'Requested scopes (JSON array)', type: 'json', value: []},
      {name: 'config', label: 'Provider configuration (JSON object)', type: 'json', value: {}, hint: 'API keys require header_name. OAuth requires client_id. Remote OAuth also requires issuer, resource and allowed_origin using exact HTTPS values. Broad Google Drive scopes require broad_scope_acknowledged and provider verification.'}
    ], 'Create connection', data => {
      if (data.provider === 'remote_oauth' && ['client_id', 'issuer', 'resource', 'allowed_origin'].some(key => !data.config?.[key])) throw new Error('Remote OAuth requires config.client_id, config.issuer, config.resource and config.allowed_origin.');
      return api('/api/v1/connections', 'POST', data);
    }, 'GitHub, Google and Slack connect native provider tools. OAuth remote MCP connects a remote server account; after consent, register its MCP endpoint separately and select this connection.');
    heading(target, 'connections', action('Add connection', create, 'primary'), action('Refresh list', route, '', 'refresh'));
    const rows = listOf(result, 'connections');
    if (!rows.length) target.append(empty('No account connections. Add credentials or create an OAuth connection before binding an authenticated server.'));
    for (const row of rows) {
      const item = summaryRow(row.alias, row.status, [`Provider: ${row.provider}`, `Identity: ${row.identity || 'Not confirmed'}`, `Expires: ${row.expires_at ? time(row.expires_at) : 'Not supplied'}`],
        action('Edit connection', () => formModal('Update connection', [
          {name: 'alias', label: 'Account alias', value: row.alias, required: true, pattern: '[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', maxlength: 80, hint: 'Use letters, digits, dots, underscores or hyphens; no spaces.'},
          {name: 'identity', label: 'Account identity', value: row.identity || '', placeholder: 'e.g. you@company.com (shown in audit events)'},
          {name: 'secret', label: 'Replacement secret', type: 'password', placeholder: 'New secret (optional)', hint: 'Leave empty to keep the current credential.'},
          {name: 'scopes', label: 'Requested scopes (JSON array)', type: 'json', value: row.scopes, hint: 'Used again at the next consent or token refresh.'},
          {name: 'config', label: 'Provider configuration (JSON object)', type: 'json', value: row.config, hint: 'Merged over the stored configuration. API keys require header_name; see Add connection for the rules. The provider itself never changes here - create a new connection for that.'}
        ], 'Save connection', data => {
          if (data.scopes !== undefined && (!Array.isArray(data.scopes) || data.scopes.some(scope => typeof scope !== 'string' || !scope))) throw new Error('Scopes must be a JSON array of non-empty strings.');
          return api(idPath('connections', row.id), 'PATCH', data);
        }), '', 'pencil'),
        action('Delete', () => confirmAction('Delete connection', 'Removes this stored account permanently. Only possible when no MCP server still uses it. Stored credentials are destroyed.', () => api(idPath('connections', row.id), 'DELETE'), 'Delete connection'), 'danger', 'trash'),
        ...(row.provider === 'api_key' || row.provider === 'bearer' ? [] : [action('Connect OAuth', async () => {
          const data = await api(idPath('connections', row.id, '/oauth/start'), 'POST');
          const url = new URL(data.authorization_url);
          if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('The OAuth provider returned an unsupported authorization URL.');
          modal('Continue to provider', p(`Review account and requested scopes before granting consent. Provider: ${url.hostname}`), p(`Requested scopes: ${(row.scopes || []).join(', ') || 'None configured'}`), el('a', {href: url.href, rel: 'noopener noreferrer'}, 'Open provider authorization'));
        })]),
        action('Revoke', () => confirmAction('Revoke account connection', 'The credential and future tool access through this connection will be revoked. Check clients using this account before continuing.', () => api(idPath('connections', row.id, '/revoke'), 'POST'), 'Revoke connection'), 'danger', 'ban'));
      item.append(p(`Scopes: ${(row.scopes || []).join(', ') || 'None disclosed'}`, 'hint'), p(`Stable connection ID: ${row.id}`, 'mono'));
      target.append(item);
    }
  },
  async profiles(target) {
    const [result, toolsResult, connectionsResult, clientsResult] = await Promise.all([api('/api/v1/profiles'), api('/api/v1/tools'), api('/api/v1/connections'), api('/api/v1/clients')]);
    const tools = listOf(toolsResult, 'tools'), connections = listOf(connectionsResult, 'connections'), clients = listOf(clientsResult, 'clients');
    heading(target, 'profiles', action('Create profile', () => formModal('Create profile', [{name: 'name', label: 'Profile name', required: true, placeholder: 'e.g. Research assistant'}, {name: 'slug', label: 'URL slug (optional)', placeholder: 'e.g. research-assistant'}], 'Create profile', data => api('/api/v1/profiles', 'POST', data), 'New profiles start with no tool access. Choose allowed tools, then select the profile when issuing a client token.'), 'primary'));
    const rows = listOf(result, 'profiles');
    if (!rows.length) target.append(empty('Create a profile to choose which tools your agent clients can use.'));
    for (const row of rows) {
      const assigned = clients.filter(client => client.profile_id === row.id);
      const remove = () => {
        if (!assigned.length) return confirmAction('Delete profile', `Delete “${row.name}” and its tool grants? No clients use this profile.`, () => api(idPath('profiles', row.id), 'DELETE'), 'Delete profile');
        formModal('Delete profile', [{name: 'replacement_profile_id', label: 'Move clients to profile', type: 'select', required: true, options: [{value: '', label: 'Choose replacement access'}, ...rows.filter(other => other.id !== row.id).map(other => ({value: other.id, label: other.name}))]}], 'Move clients and delete profile', data => api(idPath('profiles', row.id), 'DELETE', data), `“${row.name}” is used by: ${assigned.map(client => client.name).join(', ')}. These clients will use the replacement profile’s tool access immediately. Existing tokens stay valid; pending call approvals and this profile’s grants are removed.`);
      };
      const item = summaryRow(row.name, row.is_default ? 'Built-in profile' : '', [`${assigned.length} client${assigned.length === 1 ? '' : 's'} using this profile`], action('Edit tool access', () => editGrants(row, tools, connections), 'primary'), action('Clone', () => formModal('Clone profile', [{name: 'name', label: 'New profile name', required: true}, {name: 'slug', label: 'New URL slug (optional)'}], 'Clone with grants', data => api(idPath('profiles', row.id, '/clone'), 'POST', data))), row.is_default ? null : action('Delete profile', remove, 'danger'));
      item.append(p(row.is_default ? 'The built-in profile cannot be deleted. Clear its tool access to block all tools for its clients.' : 'Edit grants to add or remove allowed tools. Clients sharing this profile share the same access.', 'hint'));
      target.append(item);
    }
  },
  async clients(target) {
    const [result, profiles] = await Promise.all([api('/api/v1/clients'), api('/api/v1/profiles')]);
    const profileRows = listOf(profiles, 'profiles');
    heading(target, 'clients', action('Issue client token', () => {
      if (!profileRows.length) { notify('Create a profile before issuing a client token.'); return; }
      modal('Issue client token', form([{name: 'name', label: 'Client name', required: true, placeholder: 'e.g. codex-laptop'}, {name: 'kind', label: 'Client application', type: 'select', options: ['codex', 'claude', 'cursor', 'gemini', 'hermes', 'other']}, {name: 'profile_id', label: 'Bound profile', type: 'select', required: true, options: profileRows.map(item => ({value: item.id, label: item.name}))}, {name: 'ttl_days', label: 'Expires after days (optional)', type: 'number', min: 1, max: 3650, placeholder: 'e.g. 30'}], 'Issue token', async data => {
        const created = await api('/api/v1/clients', 'POST', data); revealToken('Save client token', created.token, 'Shown once. Anyone holding this token can use this profile.', route);
      }));
    }, 'primary'));
    const rows = listOf(result, 'clients');
    if (!rows.length) target.append(empty('No agent clients. Issue a separate token for each application after reviewing its profile grants.'));
    for (const row of rows) target.append(summaryRow(row.name, row.status, [`Profile: ${profileRows.find(item => item.id === row.profile_id)?.name || row.profile_id}`, `App: ${row.kind}`, `Last used: ${time(row.last_used)}`, `Expires: ${row.expires_at ? time(row.expires_at) : 'No expiry'}`],
      action('Client config', () => {
        modal('Generate client config', form([{name: 'kind', label: 'Config format', type: 'select', value: row.kind, options: ['codex', 'claude', 'cursor', 'gemini', 'hermes', 'other']}], 'Generate config', async data => {
          const config = await api(`${idPath('clients', row.id, '/config')}?kind=${encodeURIComponent(data.kind)}`);
          const snippet = typeof config.snippet === 'string' ? config.snippet : JSON.stringify(config.snippet, null, 2);
          modal('Client configuration', p(typeof config.instructions === 'string' ? config.instructions : JSON.stringify(config.instructions)), p('Set the token through the referenced environment variable. Compatibility depends on the installed client version and remote HTTP transport support.', 'hint'), code(snippet), action('Copy config', () => copy(snippet), '', 'copy'));
        }));
      }, '', 'file'),
      action('Rotate token', () => confirmAction('Rotate client token', 'The existing token stops working immediately. Save the replacement and update your client environment.', async () => {
        const rotated = await api(idPath('clients', row.id, '/rotate'), 'POST');
        revealToken('Save replacement token', rotated.token, 'Shown once. The old client token has been invalidated.', route);
      }, 'Rotate token', false), '', 'refresh'),
      action('Revoke', () => confirmAction('Revoke client', 'This client loses gateway access immediately.', () => api(idPath('clients', row.id, '/revoke'), 'POST'), 'Revoke client'), 'danger', 'ban')));
  },
  async management(target) {
    const result = await api('/api/v1/management/clients');
    const verificationFields = [{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password'}, {name: 'totp', label: 'Authenticator code', required: mfaEnabled, inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.'}];
    const revealManagement = data => modal('Save management token', p('Shown once. This credential controls gateway configuration according to its scopes. Store it separately from agent tokens.'), code(data.token), actions(action('Copy management token', () => copy(data.token))), p('Set WHEREMYMCP_MANAGEMENT_TOKEN in the environment used to launch Codex, then add this configuration. Reload your MCP client after saving.', 'hint'), code(data.config), actions(action('Copy management config', () => copy(data.config)), action('I saved it', async () => { closeDialog(); await route(); }, 'primary')));
    heading(target, 'management', action('Issue management token', () => modal('Issue management token', p('Read inspects configuration. Write can change servers, replace profile access and issue agent tokens. Delete can remove servers/profiles and revoke agent clients. Provider consent and owner security remain in the dashboard.'), form([{name: 'name', label: 'Management client name', required: true, placeholder: 'e.g. codex-manager'}, {name: 'read', label: 'Read configuration and diagnostics', type: 'checkbox', value: true}, {name: 'write', label: 'Write configuration and issue agent tokens', type: 'checkbox'}, {name: 'delete', label: 'Delete servers/profiles and revoke clients', type: 'checkbox'}, {name: 'ttl_days', label: 'Expires after days', type: 'number', value: 30, min: 1, max: 365, required: true}, ...verificationFields], 'Issue management token', async data => {
      const scopes = ['read', 'write', 'delete'].filter(scope => data[scope]);
      if (!scopes.length) throw new Error('Choose at least one management scope.');
      const created = await api('/api/v1/management/clients', 'POST', {name: data.name, scopes, ttl_days: data.ttl_days, password: data.password, ...(data.totp ? {totp: data.totp} : {})});
      revealManagement(created);
    })), 'primary'));
    target.append(section('Built-in management endpoint', p('Available on every instance. No MCP server registration or profile grant is required for this endpoint.'), code(result.endpoint), p(`${result.tools_count} management tools. Each token sees only tools allowed by its scopes. Ordinary agent tokens cannot use this endpoint.`, 'hint'), details('Codex configuration', code(result.config)), p('Example: “Register this MCP server, approve its current tools, then give Default access to that server.”', 'hint')));
    if (!result.clients.length) target.append(empty('No management clients yet. Issue a dedicated token to let an agent manage this instance.'));
    for (const row of result.clients) target.append(summaryRow(row.name, row.status, [`Scopes: ${row.scopes.join(', ')}`, `Expires: ${time(row.expires_at)}`, `Last used: ${time(row.last_used)}`], row.status === 'active' && row.expires_at > Date.now() ? action('Rotate management token', () => modal('Rotate management token', p('The old management token stops working immediately.'), form(verificationFields, 'Rotate management token', async data => revealManagement(await api(idPath('management/clients', row.id, '/rotate'), 'POST', data))))) : null, row.status === 'active' ? action('Revoke management token', () => confirmAction('Revoke management token', 'This management client loses access immediately.', () => api(idPath('management/clients', row.id, '/revoke'), 'POST'), 'Revoke management token'), 'danger') : null));
  },
  async approvals(target) {
    const [clients, tools] = await Promise.all([api('/api/v1/clients'), api('/api/v1/tools')]);
    heading(target, 'approvals');
    const active = listOf(clients, 'clients').filter(row => row.status === 'active');
    const writeable = listOf(tools, 'tools').filter(row => row.enabled && ['write', 'delete'].includes(row.risk));
    if (!active.length || !writeable.length) {
      target.append(empty(!active.length ? 'No active agent client. Issue a client token in Agent clients before approving one-use calls.' : 'No enabled write or delete tool. Review and approve tools in Tool review first.'));
      return;
    }
    target.append(section('Approve exact call', p('Inspect the complete argument object first. Approval is bound to its fingerprint and can be consumed once. Pass the returned ID in _meta.wheremymcp_approval_id.', 'hint'), form([
      {name: 'client_id', label: 'Client', type: 'select', required: true, options: [{value: '', label: 'Select an active client'}, ...active.map(row => ({value: row.id, label: row.name}))]},
      {name: 'tool_id', label: 'Write or delete tool', type: 'select', required: true, options: [{value: '', label: 'Select a reviewed tool'}, ...writeable.map(row => ({value: row.id, label: `${row.name || 'Unnamed tool'}${row.upstream_name ? ` · ${row.upstream_name}` : ''}`}))]},
      {name: 'arguments', label: 'Exact argument object (JSON)', type: 'json', required: true, value: {}, placeholder: '{ "text": "Hello" }'}, {name: 'ttl_seconds', label: 'Approval lifetime (seconds)', type: 'number', value: 120, min: 1, max: 300}
    ], 'Approve one call', async data => {
      if (!data.arguments || typeof data.arguments !== 'object' || Array.isArray(data.arguments)) throw new Error('Arguments must be a JSON object.');
      const result = await api('/api/v1/approvals', 'POST', data);
      reveal('One-use call approval', result.approval_id, 'Pass this approval ID with the exact client, tool and arguments shown in the form. It expires and cannot be reused.');
    })));
  },
  async skills(target) {
    const result = await api('/api/v1/skills');
    heading(target, 'skills', action('Import for review', () => modal('Import skill files', p('Preview file contents before importing. Import does not approve or execute a skill.', 'hint'), form([{name: 'name', label: 'Skill name', required: true, placeholder: 'e.g. release-notes'}, {name: 'source', label: 'Source reference', required: true, placeholder: 'e.g. github:org/repo/skills/release-notes'}, {name: 'files', label: 'File map (JSON object)', type: 'json', required: true, placeholder: '{ "SKILL.md": "--- name: ... file contents" }', hint: 'Map relative file paths to their full text contents. Include SKILL.md. Unsafe paths are rejected; file contents are never executed.'}], 'Preview import', async data => {
      if (!data.files || typeof data.files !== 'object' || Array.isArray(data.files)) throw new Error('Files must be a JSON object mapping relative paths to text.');
      modal('Review import contents', p(`Skill: ${data.name} · Source: ${data.source}`), ...Object.entries(data.files).map(([name, content]) => details(name, code(content))), action('Import unapproved skill', async () => { await api('/api/v1/skills', 'POST', data); closeDialog(); await route(); notify('Skill imported. Inspect and approve it separately.'); }, 'primary'));
    })), 'primary'));
    const rows = listOf(result, 'skills');
    if (!rows.length) target.append(empty('No reviewed skill files. Import a file map to preview and approve a skill. Use the CLI for dry-run installation into an explicit target directory.'));
    for (const row of rows) {
      const item = summaryRow(row.name, row.approved ? 'Approved' : 'Needs review', [`Source: ${row.source}`, `Imported: ${time(row.created_at)}`, `Digest: ${row.digest}`], action('Approve', () => confirmAction('Approve skill files', 'Mark these exact reviewed files as approved for explicit CLI sync. This never executes the content.', () => api(idPath('skills', row.id, '/approve'), 'POST'), 'Approve files'), '', 'check'), action('Delete', () => confirmAction('Delete skill', 'Remove these stored files from this instance. Existing files previously synced by CLI remain on disk.', () => api(idPath('skills', row.id), 'DELETE'), 'Delete skill'), 'danger', 'trash'));
      const content = row.files || (typeof row.content === 'string' ? JSON.parse(row.content) : row.content);
      if (content && typeof content === 'object') item.append(details('Inspect stored files', Object.entries(content).map(([name, text]) => details(name, code(text)))));
      else item.append(p('Preview is not included in the server response. Do not approve unless you have reviewed the imported file contents.', 'hint'));
      target.append(item);
    }
  },
  async security(target) {
    const [session, overview] = await Promise.all([api('/auth/session'), api('/api/v1/overview')]); mfaEnabled = !!session.mfa_enabled;
    heading(target, 'security');
    target.append(section('Owner authenticator', p(mfaEnabled ? 'MFA is enabled for this owner.' : 'MFA is not enabled. Public mode requires MFA.'), mfaEnabled ? action('Disable MFA', () => formModal('Disable owner MFA', [{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}, {name: 'totp', label: 'Current authenticator code', required: true, autocomplete: 'one-time-code', inputmode: 'numeric', placeholder: '6-digit code'}], 'Disable MFA', data => api('/auth/mfa/disable', 'POST', data)), 'danger') : action('Set up MFA', async () => {
      const setup = await api('/auth/mfa/setup', 'POST');
      const qrHolder = el('div', {class: 'qr'});
      if (setup.qr_svg) { const doc = new DOMParser().parseFromString(setup.qr_svg, 'image/svg+xml'); const svg = doc.documentElement; if (svg && svg.nodeName === 'svg') qrHolder.append(document.importNode(svg, true)); }
      modal('Set up your authenticator', p('Scan the QR code with your authenticator app, or add the secret manually below. Keep it private, then enter a current code to confirm setup.'), qrHolder, setup.qr_svg ? null : p('QR code unavailable; use the secret below.', 'hint'), details('Manual entry', code(setup.secret), true), details('Authenticator URI', code(setup.uri)), action('Copy setup secret', () => copy(setup.secret), '', 'copy'), form([{name: 'totp', label: 'Authenticator code', required: true, inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '6-digit code'}], 'Enable MFA', async data => { await api('/auth/mfa/enable', 'POST', data); closeDialog(); await route(); notify('Owner MFA enabled.'); }));
    }, 'primary')),
    section('Owner recovery & password', p('Change your password here any time. If you lose it and have no unused recovery code, there is no email reset: a single instance has no account recovery service, so keep the password and one code offline.', 'hint'), actions(
      action('Change owner password', () => formModal('Change owner password', [{name: 'password', label: 'Current owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Current password'}, {name: 'new_password', label: 'New owner password', type: 'password', required: true, minlength: 8, maxlength: 256, autocomplete: 'new-password', placeholder: 'Min. 8: lowercase, uppercase, number, symbol'}, {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.', placeholder: '6-digit code'}], 'Save new password', data => api('/auth/password', 'POST', data))),
      action('Replace recovery codes', () => modal('Replace recovery codes', p('Every previous recovery code will stop working. Save the replacements offline.'), form([{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}, {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.', placeholder: '6-digit code'}], 'Generate replacement codes', async data => {
        const result = await api('/auth/recovery-codes', 'POST', data);
        reveal('Save replacement recovery codes', result.recovery_codes.join('\n'), 'Shown once. Previous recovery codes are invalid. Store each replacement offline; each can be consumed once.');
      })))
    )),
    section('Emergency stop', p(overview.emergency_stop ? 'All gateway tool calls are stopped.' : 'Gateway policy is active. Emergency stop denies all agent tool calls.'), action(overview.emergency_stop ? 'Resume gateway calls' : 'Stop all gateway calls', () => stopControl(!overview.emergency_stop), 'danger')));
  },
  async audit(target) {
    heading(target, 'audit');
    let nextBefore;
    let nextCursor;
    let filters = {};
    const results = el('div');
    const more = action('Load older events', () => load(true)); more.hidden = true;
    async function load(append = false) {
      more.disabled = true;
      if (!append) results.replaceChildren(p('Loading audit events…', 'muted'));
      try {
        const params = new URLSearchParams({limit: '50', ...filters});
        if (append && nextCursor) params.set('cursor', nextCursor);
        else if (append && nextBefore) params.set('before', String(nextBefore));
        const result = await api(`/api/v1/audit?${params}`); nextBefore = result.next_before; nextCursor = result.next_cursor;
        if (!append) results.replaceChildren();
        results.append(eventsView(result.events || [])); more.hidden = !nextBefore && !nextCursor;
      } catch (error) { if (!append) results.replaceChildren(errorBlock(error, () => load())); else notify(error.message); }
      finally { more.disabled = false; }
    }
    const filtersForm = form([{name: 'action', label: 'Action', placeholder: 'e.g. tool.call'}, {name: 'outcome', label: 'Outcome', placeholder: 'e.g. denied'}, {name: 'principal', label: 'Principal / client ID', placeholder: 'owner or client ID'}, {name: 'resource', label: 'Resource / tool ID', placeholder: 'tool or resource ID'}, {name: 'profile_id', label: 'Historical profile ID', placeholder: 'Profile UUID'}, {name: 'account_id', label: 'Historical account ID', placeholder: 'Account UUID'}, {name: 'account_alias', label: 'Account alias at event', maxlength: 80, placeholder: 'Alias as recorded at the event', hint: 'Matches the recorded alias, including an alias that has since changed.'}, {name: 'from', label: 'From (local time)', type: 'datetime-local', placeholder: '2026-01-31T14:30'}, {name: 'to', label: 'Until (local time)', type: 'datetime-local', placeholder: '2026-02-28T18:00'}], 'Apply filters', async data => {
      filters = {...data}; for (const key of ['from', 'to']) if (data[key]) filters[key] = String(new Date(data[key]).getTime()); await load();
    });
    filtersForm.classList.add('toolbar'); target.append(details('Filter policy events', filtersForm), section('Recorded decisions', results, more)); await load();
  },
  async backups(target) {
    const result = await api('/api/v1/backups');
    heading(target, 'backups', action('Create encrypted backup', () => formModal('Create encrypted backup', [{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}, {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.', placeholder: '6-digit code'}], 'Create backup', data => api('/api/v1/backup/create', 'POST', data), 'Retain the external master key separately. A backup cannot recover vault credentials if that key is lost.'), 'primary'), action('Export config', async () => { const data = await api('/api/v1/config/export'); jsonDownload('wheremymcp-config.json', data); notify('Configuration exported without stored credentials.'); }), action('Import config', importConfig));
    target.append(section('Restore readiness', p('Keep the external master key separately from encrypted backups. Test restore into a fresh, offline destination using the CLI before relying on a backup.'), p('Restore verification is not tracked by this dashboard. A listed backup is not proof of a successful restore.', 'hint')));
    const rows = listOf(result, 'backups').sort((a, b) => b.created_at - a.created_at);
    if (!rows.length) target.append(empty('No encrypted backups exist yet. Create one, then run a restore drill with the external master key.'));
    for (const row of rows) target.append(summaryRow(row.name, 'Encrypted backup', [`Created: ${time(row.created_at)}`, `Size: ${Number(row.size).toLocaleString()} bytes`], action('Download encrypted backup', () => formModal('Download encrypted backup', [{name: 'password', label: 'Owner password', type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Your owner password'}, {name: 'totp', label: 'Authenticator code', inputmode: 'numeric', autocomplete: 'one-time-code', hint: 'Required when MFA is enabled.', placeholder: '6-digit code'}], 'Download backup file', data => downloadBackup(row.name, data), 'The downloaded file stays encrypted. Keep its external master key separately.'))));
    target.append(section('Move to another instance', p('Export configuration, create an encrypted backup and retain its external master key. Stop the destination instance and restore into an empty directory using the CLI. Check diagnostics and client access before switching traffic.'), p('Credential-free config export helps review a move but cannot recreate stored secrets on its own.', 'hint')));
  },
  async settings(target) {
    const [settings, diagnostics] = await Promise.all([api('/api/v1/settings'), api('/api/v1/system/diagnostics')]);
    heading(target, 'settings', action('Refresh diagnostics', route, '', 'refresh'));
    const tlsStatus = diagnostics.public_mode
      ? 'Public mode expects HTTPS at the configured trusted reverse proxy. The hub cannot inspect the proxy certificate.'
      : 'Local mode uses HTTP and must stay loopback-only. Do not expose this port directly.';
    target.append(section('Transport security', p(tlsStatus), p(`Configured origin: ${diagnostics.origin}. Trusted proxy addresses: ${diagnostics.trusted_proxy_count}.`, 'hint')),
      section('Database migration', p(`Schema ${diagnostics.schema_version} of ${diagnostics.supported_schema_version}; status: ${diagnostics.migration_status}.`), p('A newer unsupported database stops startup. Back up before upgrading; failed upgrades retain a pre-migration database copy beside the SQLite file.', 'hint')),
      section('Runtime diagnostics', code(diagnostics)), section('Instance settings', p('Audit retention is editable here. Runtime configuration remains controlled by the environment and startup config.', 'hint'), form([{name: 'audit_retention_days', label: 'Audit retention (days)', type: 'number', required: true, min: 1, max: 365, value: settings.audit_retention_days}], 'Save settings', async data => {
      await api('/api/v1/settings', 'PATCH', data); await route(); notify('Settings saved.');
    }), details('Read-only runtime settings', code(settings))));
  }
};
initNav();
let theme;
try { theme = localStorage.getItem('wheremymcp-theme') || localStorage.getItem('unifymcp-theme'); } catch { /* Browser storage may be disabled. */ }
function setTheme(value) {
  document.documentElement.dataset.theme = value;
  $('#theme-toggle').textContent = value === 'dark' ? 'Light theme' : 'Dark theme';
  $('#theme-toggle').setAttribute('aria-label', `Switch to ${value === 'dark' ? 'light' : 'dark'} theme`);
}
setTheme(theme === 'light' || theme === 'dark' ? theme : matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
$('#theme-toggle').addEventListener('click', () => { const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; setTheme(next); try { localStorage.setItem('wheremymcp-theme', next); } catch { /* Theme still applies without persistence. */ } });
$('#menu-toggle').addEventListener('click', () => { nav.hidden = !nav.hidden; $('#menu-toggle').setAttribute('aria-expanded', String(!nav.hidden)); });
$('#logout').addEventListener('click', () => run(async () => { await api('/auth/logout', 'POST', {}); csrf = ''; authenticated = false; viewVersion++; closeDialog(); showLogin(); }));
$('#emergency-stop').addEventListener('click', () => run(() => stopControl(true)));
window.addEventListener('hashchange', () => run(route));
let compactNavigation = window.innerWidth < 928;
window.addEventListener('resize', () => {
  const nextCompact = window.innerWidth < 928;
  if (authenticated && nextCompact !== compactNavigation) {
    nav.hidden = nextCompact;
    $('#menu-toggle').setAttribute('aria-expanded', String(!nextCompact));
  }
  compactNavigation = nextCompact;
});
window.addEventListener('keydown', event => { if (event.key === 'Escape' && !dialog.open && window.innerWidth < 928) { nav.hidden = true; $('#menu-toggle').setAttribute('aria-expanded', 'false'); $('#menu-toggle').focus(); } });
dialog.addEventListener('cancel', () => dialog.replaceChildren());
run(boot);
