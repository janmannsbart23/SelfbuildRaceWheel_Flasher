/*
 * Copyright (c) 2024-2026 Jan Lenz
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Free for personal and other noncommercial use. Commercial use requires permission.
 * License: LICENSE.md in the repository root or https://polyformproject.org/licenses/noncommercial/1.0.0
 */

/*
 * install.js – USB installation with esptool-js (bootloader, partition table, UDS bootloader, app)
 *
 * The parts come from the manifest (install.parts: offset + file, or fill/size). esptool-js 0.7.0 is
 * kept unchanged in vendor/ (Apache-2.0), including the flasher stubs for ESP32-S3 and ESP32-P4.
 */
import { ESPLoader, Transport } from '../vendor/esptool-js-0.7.0/esptool.bundle.js';
import { buildFits, fmtRev } from './core.js';

const BAUD = 921600;

/**
 * Connect to the ESP32 in download mode.
 * Result: { loader, transport, chip: 'ESP32-S3', rev: 301 | null, description }
 */
export async function connectEsp(port, log) {
	const transport = new Transport(port, false);
	const terminal = {
		clean() {},
		writeLine: (s) => log(s),
		write: (s) => { if (s.trim()) log(s.trim()); },
	};
	const loader = new ESPLoader({ transport, baudrate: BAUD, romBaudrate: 115200, terminal, debugLogging: false });
	const description = await loader.main('default_reset');
	const chip = loader.chip.CHIP_NAME;
	let rev = null;
	if (loader.chip.getChipRevision) {
		try { rev = await loader.chip.getChipRevision(loader); } catch (e) { /* older chips */ }
	}
	return { loader, transport, chip, rev, description };
}

/**
 * Manifest products that fit the detected chip, the one with the highest minimum revision first
 * (ESP32-P4: the build for < v3.0 often has no upper limit, the one for ≥ v3.0 requires v3.0)
 */
export function candidatesFor(products, chip, rev) {
	return products
		.filter((p) => p.install && buildFits(p, chip, rev))
		.sort((a, b) => (b.chipRev?.min ?? 0) - (a.chipRev?.min ?? 0));
}

export function describeRev(p) {
	if (!p.chipRev) return '';
	const { min, max } = p.chipRev;
	if (max != null) return `chip rev. ${fmtRev(min)}–${fmtRev(max)}`;
	return min ? `chip rev. ${fmtRev(min)} and later` : '';
}

/**
 * Load and write the parts.
 *   fetchFile(rel) -> Promise<Uint8Array>
 *   onProgress(done, total, text)
 */
export async function installProduct(conn, product, { fetchFile, eraseAll = false, onProgress = () => {}, log = () => {} }) {
	const parts = product.install.parts;
	const files = [];
	for (const p of parts) {
		let data;
		if (p.file) {
			onProgress(0, 1, `Loading ${p.file} …`);
			data = await fetchFile(p.file, p.sha256);
			if (p.size && data.length !== p.size) throw new Error(`${p.file}: size does not match the manifest`);
		} else {
			data = new Uint8Array(p.size).fill(p.fill ?? 0xff);
		}
		files.push({ data, address: p.offset });
		log(`0x${p.offset.toString(16).padStart(6, '0')}  ${p.file || `empty (${p.size} bytes)`}`);
	}
	const total = files.reduce((a, f) => a + f.data.length, 0);
	const before = files.map((_, i) => files.slice(0, i).reduce((a, f) => a + f.data.length, 0));
	if (eraseAll) onProgress(0, total, 'Erasing the whole flash …');
	await conn.loader.writeFlash({
		fileArray: files,
		flashMode: 'keep',
		flashFreq: 'keep',
		flashSize: 'keep',
		eraseAll,
		compress: true,
		reportProgress: (i, written, size) => {
			const done = before[i] + Math.round(files[i].data.length * (written / Math.max(1, size)));
			onProgress(done, total, `Writing part ${i + 1}/${files.length} …`);
		},
	});
	onProgress(total, total, 'Restarting …');
	await conn.loader.after('hard_reset');
}

export async function disconnectEsp(conn) {
	try { await conn.transport.disconnect(); } catch (e) { /* already closed */ }
}
