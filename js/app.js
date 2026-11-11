/*
 * Copyright (c) 2024-2026 Jan Lenz
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Free for personal and other noncommercial use. Commercial use requires permission.
 * License: LICENSE.md in the repository root or https://polyformproject.org/licenses/noncommercial/1.0.0
 */

/*
 * app.js – user interface of the web flasher
 *   Update via dongle:  Web Serial -> SlcanLink -> Discovery/flashDevice (core.js)
 *   USB installation:   Web Serial -> esptool-js (install.js, loaded on demand)
 */
import * as C from './core.js';

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
	const e = document.createElement(tag);
	for (const [k, v] of Object.entries(attrs)) {
		if (k === 'class') e.className = v;
		else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
		else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
	}
	for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : String(k));
	return e;
};
const store = {
	get(k, d = null) { try { const v = localStorage.getItem(`rw.${k}`); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
	set(k, v) { try { localStorage.setItem(`rw.${k}`, JSON.stringify(v)); } catch (e) { /* private mode */ } },
};

// --------------------------------------------------------------------------- State
const S = {
	manifest: null,
	products: [],
	port: null,
	reader: null,
	link: null,
	disc: null,
	busy: false,
	signal: null,
	files: {},              // dev.key -> {name, bytes}
	choice: {},             // dev.key -> product id (when several products fit)
	lastProbe: 0,
};

// --------------------------------------------------------------------------- Log
const logEl = $('log');
function log(text) {
	const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
	logEl.textContent += `${t}  ${text}\n`;
	if (logEl.textContent.length > 400000) logEl.textContent = logEl.textContent.slice(-300000);
	logEl.scrollTop = logEl.scrollHeight;
}
$('btn-log-clear').onclick = () => { logEl.textContent = ''; };
$('btn-log-copy').onclick = () => navigator.clipboard?.writeText(logEl.textContent);

// --------------------------------------------------------------------------- Versions
const vparts = (v) => String(v || '').split('.').map((x) => parseInt(x, 10) || 0);
function vcmp(a, b) {
	const x = vparts(a), y = vparts(b);
	for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
	return 0;
}

// --------------------------------------------------------------------------- Manifest
async function loadManifest() {
	try {
		const r = await fetch('firmware/manifest.json', { cache: 'no-cache' });
		if (!r.ok) throw new Error(`HTTP ${r.status}`);
		S.manifest = await r.json();
		S.products = S.manifest.products || [];
		const d = S.manifest.generated ? new Date(S.manifest.generated).toLocaleDateString('en-GB') : '';
		$('release').textContent = `Firmware release ${d} · ${S.products.length} ${S.products.length === 1 ? 'package' : 'packages'}`;
	} catch (e) {
		S.manifest = null;
		S.products = [];
		$('release').textContent = 'No firmware release found – own files only';
		$('chk-files').checked = true;
		log(`firmware/manifest.json not loaded (${e.message})`);
	}
	updateKeyHint();
	fillInstallSelect();
}

async function fetchFile(rel, sha) {
	const r = await fetch(`firmware/${rel}`, { cache: 'no-cache' });
	if (!r.ok) throw new Error(`${rel}: HTTP ${r.status}`);
	const u8 = new Uint8Array(await r.arrayBuffer());
	if (sha && crypto.subtle) {
		const h = C.hex(new Uint8Array(await crypto.subtle.digest('SHA-256', u8)), '').toLowerCase();
		if (h !== sha) throw new Error(`${rel}: checksum mismatch (download damaged?)`);
	}
	return u8;
}

// --------------------------------------------------------------------------- Settings
const keyInp = $('inp-key');
keyInp.value = store.get('udsKey', '') || '';
keyInp.addEventListener('change', () => {
	const v = keyInp.value.trim();
	if (v) {
		try { C.parseKey(v); keyInp.setCustomValidity(''); } catch (e) { keyInp.setCustomValidity(e.message); keyInp.reportValidity(); return; }
	}
	store.set('udsKey', v);
	updateKeyHint();
});
function currentKey() {
	const v = keyInp.value.trim() || S.manifest?.udsKey || '';
	return v ? C.parseKey(v) : null;
}
function updateKeyHint() {
	const own = keyInp.value.trim();
	$('key-hint').textContent = own
		? 'Own key – stored in this browser only.'
		: S.manifest?.udsKey ? 'Empty = key from the firmware release.' : 'The firmware release contains no key – enter it if the device asks for one.';
}

// connection profile (same values as the UDS tool's "Connection" tab)
const profSel = $('sel-profile');
profSel.replaceChildren(...Object.entries(C.LINK_PROFILES).map(([id, p]) => el('option', { value: id }, p.label)));
profSel.value = C.LINK_PROFILES[store.get('linkProfile')] ? store.get('linkProfile') : 'wireless';
function showProfile() {
	const p = C.LINK_PROFILES[profSel.value];
	$('profile-hint').textContent = `STmin ≥ ${p.stMinMs} ms · blocks ≤ ${p.maxBlock || 'device maximum'} bytes · `
		+ `${p.interBlockMs} ms between blocks · ${p.blockRetries} block retries · answer timeout ${p.p2Ms} ms`;
}
profSel.onchange = () => { store.set('linkProfile', profSel.value); showProfile(); };
showProfile();

$('chk-files').addEventListener('change', () => renderDevices(true));
$('chk-trace').addEventListener('change', () => {
	if (S.link) S.link.trace = $('chk-trace').checked ? (d, t) => log(`${d === 'tx' ? '→' : '←'} ${t}`) : null;
});

// --------------------------------------------------------------------------- Tabs
for (const [tab, pane] of [['tab-update', 'pane-update'], ['tab-install', 'pane-install']]) {
	$(tab).onclick = () => {
		if (S.busy) return;
		for (const t of document.querySelectorAll('.tab')) t.setAttribute('aria-selected', String(t.id === tab));
		$('pane-update').hidden = pane !== 'pane-update';
		$('pane-install').hidden = pane !== 'pane-install';
		$('progress').hidden = true;
	};
}

// --------------------------------------------------------------------------- Progress
function progressStart(title) {
	S.busy = true;
	S.signal = { cancelled: false };
	$('progress').hidden = false;
	$('prog-title').textContent = title;
	$('prog-result').hidden = true;
	$('btn-cancel').hidden = false;
	setProgress(0, 1, 'Starting …');
	setButtons();
	$('progress').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function setProgress(done, total, text) {
	const pct = total ? Math.min(100, Math.floor((done / total) * 100)) : 0;
	$('prog-fill').style.width = `${pct}%`;
	$('prog-pct').textContent = `${pct} %`;
	if (text) $('prog-text').textContent = text;
}
function progressEnd(ok, text) {
	S.busy = false;
	$('btn-cancel').hidden = true;
	const r = $('prog-result');
	r.hidden = false;
	r.className = `result ${ok ? 'ok' : 'err'}`;
	r.textContent = text;
	log(text);
	setButtons();
	renderDevices(true);
}
$('btn-cancel').onclick = () => { if (S.signal) { S.signal.cancelled = true; $('prog-text').textContent = 'Cancelling …'; } };
window.addEventListener('beforeunload', (e) => { if (S.busy) { e.preventDefault(); e.returnValue = ''; } });

function setButtons() {
	const connected = !!S.link;
	$('btn-dongle').hidden = connected;
	$('btn-dongle-any').hidden = connected;
	$('btn-dongle-off').hidden = !connected;
	$('btn-probe').hidden = !connected;
	for (const b of document.querySelectorAll('#devices button, #btn-install, #btn-dongle-off, #btn-probe')) b.disabled = S.busy;
	$('btn-install').disabled = S.busy || !!S.link || !$('sel-install').value;
	$('btn-install').title = S.link ? 'Disconnect the dongle first' : '';
	$('install-hint').hidden = !S.link;
}

// --------------------------------------------------------------------------- Dongle (Web Serial)
async function connectDongle(anyPort) {
	if (!('serial' in navigator)) return;
	let port;
	try {
		port = await navigator.serial.requestPort(anyPort ? {} : { filters: [{ usbVendorId: 0x303a }] });
	} catch (e) {
		return;   // selection cancelled
	}
	try {
		await port.open({ baudRate: 115200, bufferSize: 65536 });
	} catch (e) {
		alert(`Cannot open the port: ${e.message}\n\nIs SimHub still running? Only one program can use the COM port at a time.`);
		return;
	}
	S.port = port;
	const writer = port.writable.getWriter();
	let onData = null;
	const stream = { write: (u8) => writer.write(u8), onData: (cb) => { onData = cb; } };
	S.writer = writer;
	S.link = new C.SlcanLink(stream);
	S.disc = new C.Discovery(S.link, () => renderDevices());
	$('chk-trace').dispatchEvent(new Event('change'));
	(async () => {
		S.reader = port.readable.getReader();
		try {
			for (;;) {
				const { value, done } = await S.reader.read();
				if (done) break;
				if (value && onData) onData(value);
			}
		} catch (e) {
			log(`Connection to the dongle lost (${e.message})`);
		} finally {
			disconnectDongle(true);
		}
	})();
	await S.link.open();
	log('Dongle connected, waiting for heartbeats …');
	setButtons();
	renderDevices(true);
}

async function disconnectDongle(lost = false) {
	if (!S.link) return;
	if (S.busy && S.signal) S.signal.cancelled = true;
	const { link, disc, reader, writer, port } = S;
	S.link = null; S.disc = null; S.reader = null; S.writer = null; S.port = null;
	link.close(); disc.close();
	try { if (!lost) await reader?.cancel(); } catch (e) { /* */ }
	try { reader?.releaseLock(); } catch (e) { /* */ }
	try { writer?.releaseLock(); } catch (e) { /* */ }
	try { await port?.close(); } catch (e) { /* */ }
	setButtons();
	renderDevices(true);
}
$('btn-dongle').onclick = () => connectDongle(false);
$('btn-dongle-any').onclick = () => connectDongle(true);
$('btn-dongle-off').onclick = () => disconnectDongle();

/**
 * Active search with TesterPresent. Finds devices whose heartbeat does not get through and makes a
 * bootloader that waits for its peer learn the dongle. quiet = automatic search, log only results.
 */
async function probe(quiet = false) {
	if (!S.link || S.busy) return;
	S.lastProbe = Date.now();
	const found = await C.probeDevices(S.link);
	if (!S.disc) return;
	if (found.length || !quiet) {
		log(found.length ? `Answer from: ${found.map((d) => `${C.DEVICE_TYPES[d.type]?.name || d.type} #${d.nr}`).join(', ')}` : 'No answer to TesterPresent');
	}
	for (const d of found) S.disc.addProbed(d);
	renderDevices(true);
}
$('btn-probe').onclick = () => probe(false);

// --------------------------------------------------------------------------- Device list
function productsFor(dev) {
	let list = S.products.filter((p) => p.type === dev.type && p.update);
	if (dev.variant != null && list.some((p) => p.variant != null)) {
		const v = list.filter((p) => p.variant === dev.variant);
		if (v.length) list = v;
	}
	if (dev.type === 8 && list.length > 1) {
		const rev = store.get('displayRev');
		if (rev != null) {
			const m = list.filter((p) => C.buildFits(p, 'ESP32-P4', rev))
				.sort((a, b) => (b.chipRev?.min ?? 0) - (a.chipRev?.min ?? 0));
			if (m.length) list = [m[0], ...list.filter((p) => p !== m[0])];
		}
	}
	return list;
}

let lastRender = '';
function renderDevices(force = false) {
	const box = $('devices');
	if (!S.link) {
		box.replaceChildren(el('p', { class: 'muted empty' }, 'Not connected yet.'));
		$('link-chips').replaceChildren();
		return;
	}
	const devs = S.disc.list().filter((d) => d.type !== 7);
	const d = S.disc.dongle;
	const live = devs.filter((x) => !x.stale);
	const chips = [
		el('span', { class: 'chip ok' }, 'Dongle'),
		d ? el('span', { class: `chip ${d.radioOk ? 'ok' : 'warn'}` }, d.radioOk ? 'Radio OK' : 'No radio link') : null,
		el('span', { class: `chip ${live.length ? 'ok' : 'warn'}` }, live.length ? 'Wheel reachable' : 'No wheel'),
		S.disc.variant ? el('span', { class: 'chip' }, C.WHEEL_VARIANTS[S.disc.variant] || `Variant ${S.disc.variant}`) : null,
	];
	$('link-chips').replaceChildren(...chips.filter(Boolean));
	const sig = JSON.stringify([devs.map((x) => [x.key, x.version, x.bootloader, x.variant, x.stale]), $('chk-files').checked, S.busy, Object.keys(S.files), S.choice]);
	if (!force && sig === lastRender) return;
	lastRender = sig;
	if (!devs.length) {
		box.replaceChildren(el('p', { class: 'muted empty' }, 'Waiting for the wheel … Is it switched on and within radio range? '
			+ 'The page also searches actively every few seconds.'));
		return;
	}
	box.replaceChildren(el('div', { class: 'devices' }, devs.map(renderDevice)));
	setButtons();
}

function renderDevice(dev) {
	const t = C.DEVICE_TYPES[dev.type] || { name: `Type 0x${dev.type.toString(16)}` };
	const cands = productsFor(dev);
	let prod = cands.find((p) => p.id === S.choice[dev.key]) || cands[0] || null;
	const own = S.files[dev.key];
	const allowFiles = $('chk-files').checked;

	let badge = null;
	if (dev.bootloader) badge = el('span', { class: 'badge new' }, dev.stale ? 'in bootloader · no heartbeat' : 'in bootloader');
	else if (prod && dev.version !== '?') {
		const c = vcmp(prod.version, dev.version);
		badge = c > 0 ? el('span', { class: 'badge new' }, 'update available') : c === 0 ? el('span', { class: 'badge ok' }, 'up to date') : el('span', { class: 'badge info' }, 'newer than the release');
	}

	const extra = [];
	if (dev.bootloader) {
		extra.push(el('span', { class: 'muted' }, 'The previous update did not finish. The device waits in its bootloader – install the firmware again.'));
	}
	if (cands.length > 1) {
		const sel = el('select', {
			onchange: (e) => { S.choice[dev.key] = e.target.value; renderDevices(true); },
		}, cands.map((p) => el('option', { value: p.id, selected: p === prod }, `${p.name} · ${p.version}`)));
		extra.push(el('span', { class: 'muted' }, dev.type === 8 ? 'Display chip revision:' : 'Package:'), sel);
	}
	if (allowFiles) {
		const inp = el('input', { type: 'file', accept: t.image === 'esp' ? '.bin' : '.hex,.bin', hidden: true });
		inp.onchange = async () => {
			const f = inp.files[0];
			if (!f) return;
			const bytes = new Uint8Array(await f.arrayBuffer());
			try {
				C.prepareUpdateImage(dev.type, f.name, bytes);
				S.files[dev.key] = { name: f.name, bytes };
				log(`${t.name}: file ${f.name} (${(bytes.length / 1024).toFixed(1)} KB)`);
			} catch (e) {
				alert(e.message);
			}
			renderDevices(true);
		};
		extra.push(inp, el('button', { class: 'btn small ghost', onclick: () => inp.click() }, own ? `File: ${own.name}` : 'Own file …'));
		if (own) extra.push(el('button', { class: 'btn small ghost', onclick: () => { delete S.files[dev.key]; renderDevices(true); } }, '×'));
	}

	const target = own ? own.name : prod ? prod.version : null;
	const btn = el('button', {
		class: 'btn primary',
		disabled: !target || S.busy,
		onclick: () => startUpdate(dev, own ? null : prod, own),
	}, target ? (own ? 'Flash file' : dev.bootloader ? `Install ${prod.version}` : `Update to ${prod.version}`) : 'No package');

	return el('div', { class: 'dev' },
		el('div', {},
			el('div', { class: 'dev-name' }, t.name, dev.nr > 1 ? ` #${dev.nr}` : ''),
			el('div', { class: 'dev-meta' },
				el('span', {}, dev.bootloader ? 'bootloader ' : 'installed ', el('b', {}, dev.version)),
				prod ? el('span', {}, 'available ', el('b', {}, prod.version)) : el('span', {}, 'no package in this release'),
				badge)),
		el('div', { class: 'dev-actions' }, btn),
		extra.length ? el('div', { class: 'dev-extra' }, extra) : null);
}

// refresh the list; search actively while no live device is seen
setInterval(() => {
	if (!S.link || S.busy) return;
	renderDevices();
	if (!S.disc.list().some((d) => !d.stale) && Date.now() - S.lastProbe > 5000) probe(true);
}, 1000);

// --------------------------------------------------------------------------- Update (UDS)
async function startUpdate(dev, prod, own) {
	if (S.busy || !S.link) return;
	const t = C.DEVICE_TYPES[dev.type];
	let key;
	try { key = currentKey(); } catch (e) { alert(e.message); return; }
	const label = `${t.name}${own ? ` – ${own.name}` : ` → ${prod.version}`}`;
	if (!confirm(`${label}\n\nKeep the wheel switched on and the dongle plugged in during the update. Start now?`)) return;
	progressStart(label);
	try {
		let bytes, name;
		if (own) { bytes = own.bytes; name = own.name; } else {
			setProgress(0, 1, 'Loading firmware …');
			bytes = await fetchFile(prod.update.file, prod.update.sha256);
			name = prod.update.file;
		}
		const image = C.prepareUpdateImage(dev.type, name, bytes);
		if (image.info) log(`Image: ${image.info.chip}, chip revision ≥ ${C.fmtRev(image.info.minRev)}${image.info.appVersion ? `, ${image.info.project} ${image.info.appVersion}` : ''}`);
		const res = await C.flashDevice({
			link: S.link, dev, image, key, discovery: S.disc, signal: S.signal,
			progress: setProgress, log, opts: C.LINK_PROFILES[profSel.value],
		});
		const want = own ? null : prod.version;
		if (res.version && want && res.version !== want) progressEnd(false, `Flashed, but the device reports version ${res.version} instead of ${want}.`);
		else if (res.version) progressEnd(true, `Done – ${t.name} runs version ${res.version}.`);
		else progressEnd(true, 'Flashed. The device has not reported back yet – switch the wheel off and on if needed.');
	} catch (e) {
		const boot = e.inBootloader ? ' The device stays in its bootloader – start the update again.' : '';
		if (e instanceof C.CancelledError) progressEnd(false, `Cancelled.${boot}`);
		else progressEnd(false, `Error: ${e.message}.${boot}`);
		console.error(e);
	}
}

// --------------------------------------------------------------------------- USB installation
const INSTALL_GROUPS = [
	{ id: 'wheel_esp', label: 'Wheel ESP32', type: 6 },
	{ id: 'display', label: 'Display (chip revision is detected)', type: 8 },
	{ id: 'dongle', label: 'USB dongle', type: 7 },
];
function fillInstallSelect() {
	const sel = $('sel-install');
	const opts = [];
	for (const g of INSTALL_GROUPS) {
		const ps = S.products.filter((p) => p.type === g.type && p.install);
		if (!ps.length) continue;
		if (g.type === 8) opts.push(el('option', { value: `group:${g.type}` }, `${g.label} · ${ps[0].version}`));
		else for (const p of ps) opts.push(el('option', { value: p.id }, `${p.name} · ${p.version}`));
	}
	if (!opts.length) opts.push(el('option', { value: '' }, 'No firmware release loaded'));
	sel.replaceChildren(...opts);
	const last = store.get('installChoice');
	if (last && [...sel.options].some((o) => o.value === last)) sel.value = last;
	sel.onchange = () => { store.set('installChoice', sel.value); setButtons(); };
	setButtons();
}

$('btn-install').onclick = async () => {
	if (S.busy || !('serial' in navigator)) return;
	const choice = $('sel-install').value;
	if (!choice) return;
	let port;
	try { port = await navigator.serial.requestPort(); } catch (e) { return; }
	progressStart('USB installation');
	const chips = $('usb-chips');
	chips.replaceChildren(el('span', { class: 'chip' }, 'connecting …'));
	let conn = null;
	let mod;
	try {
		mod = await import('./install.js');
		setProgress(0, 1, 'Connecting to the ESP32 (download mode) …');
		try {
			conn = await mod.connectEsp(port, log);
		} catch (e) {
			throw new Error(`No connection to the ESP32 (${e.message}). Hold BOOT, press RESET or replug, release BOOT, then try again`);
		}
		chips.replaceChildren(el('span', { class: 'chip ok' }, conn.description));
		log(`Detected: ${conn.description}`);

		let prod;
		if (choice.startsWith('group:')) {
			const type = Number(choice.slice(6));
			const list = mod.candidatesFor(S.products.filter((p) => p.type === type), conn.chip, conn.rev);
			if (!list.length) throw new Error(`No package for ${conn.description} in this release`);
			prod = list[0];
		} else {
			prod = S.products.find((p) => p.id === choice);
			if (prod.chip !== conn.chip) throw new Error(`The connected chip is an ${conn.chip}, "${prod.name}" is for ${prod.chip}. Right device / port?`);
			if (!mod.candidatesFor([prod], conn.chip, conn.rev).length) throw new Error(`"${prod.name}" does not fit chip revision ${C.fmtRev(conn.rev)}`);
		}
		if (prod.type === 8 && conn.rev != null) store.set('displayRev', conn.rev);
		$('prog-title').textContent = `${prod.name} · ${prod.version}`;
		log(`Installing ${prod.name} ${prod.version} (${prod.install.parts.length} parts)`);
		await mod.installProduct(conn, prod, {
			fetchFile, eraseAll: $('chk-erase').checked, onProgress: setProgress, log,
		});
		progressEnd(true, `Done – ${prod.name} ${prod.version} is installed. The device restarts.`);
	} catch (e) {
		console.error(e);
		progressEnd(false, `Error: ${e.message}.`);
		chips.replaceChildren(el('span', { class: 'chip err' }, 'not installed'));
	} finally {
		if (conn) await mod.disconnectEsp(conn);
		else try { await port.close(); } catch (e) { /* not open */ }
	}
};

// --------------------------------------------------------------------------- Start
if (!('serial' in navigator)) {
	$('no-serial').hidden = false;
	for (const b of ['btn-dongle', 'btn-dongle-any', 'btn-install']) $(b).disabled = true;
}
loadManifest().then(() => { setButtons(); if (!('serial' in navigator)) $('btn-install').disabled = true; });
