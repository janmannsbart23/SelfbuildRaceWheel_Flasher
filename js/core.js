/*
 * Copyright (c) 2024-2026 Jan Lenz
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Free for personal and other noncommercial use. Commercial use requires permission.
 * License: LICENSE.md in the repository root or https://polyformproject.org/licenses/noncommercial/1.0.0
 */

/*
 * core.js – protocol core of the RaceWheel web flasher (no DOM, also runs in Node)
 *
 *   PC ──Web Serial (SLCAN)── dongle ──ESP-NOW── wheel ESP ──CAN── STM32 / display
 *
 *   SlcanLink   SLCAN lines <-> CAN frames; send window paced by the dongle's z/Z acknowledgements
 *   IsoTp       ISO 15765-2 (29 bit, normal addressing, padding 0x00), FlowControl BS/STmin
 *   UdsClient   request/response, NRC 0x78 (responsePending), errors as UdsError
 *   Discovery   devices from the heartbeat 0x1144F0TT, variant from 0x401, dongle status 0x222
 *   flashDevice same sequence as the UDS tool: broadcast, 10 02, 27 01/02, 34, 36…, 37, 11 01
 *
 * IDs (ESP32_Library / STM32_Library): UDS 0x1144TTNN, response +0x40, heartbeat 0x1144F0TT|NN,
 * flash broadcast 0x114400FF | TT << 8 (byte 0: 1 = update running, 0 = done).
 */

// --------------------------------------------------------------------------- Device types
export const DEVICE_TYPES = {
	0x05: { key: 'wheel_stm', name: 'Wheel (STM32)', image: 'stm32' },
	0x06: { key: 'wheel_esp', name: 'Wheel ESP32', image: 'esp', chip: 'ESP32-S3' },
	0x07: { key: 'dongle', name: 'USB dongle', image: 'esp', chip: 'ESP32-S3', usbOnly: true },
	0x08: { key: 'display', name: 'Display (AdvancedDisplayWheel)', image: 'esp', chip: 'ESP32-P4' },
};
export const WHEEL_VARIANTS = { 1: 'BasicGT3', 2: 'AdvancedGT3', 3: 'AdvancedDisplayWheel' };

export const UDS_BASE = 0x11440000;
export const RX_OFFSET = 0x40;
export const HB_BASE = 0x1144f000;
export const STM32_APP_ADDR = 0x08008000;
export const STM32_APP_MAX = 164 * 1024;   // the wheels' linker script ends at 0x08031000

export const udsRequestId = (type, nr) => (UDS_BASE | (type << 8) | nr) >>> 0;
export const flashBroadcastId = (type) => (0x114400ff | ((type & 0x0f) << 8)) >>> 0;

export const hex = (u8, sep = ' ') => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join(sep).toUpperCase();
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class CancelledError extends Error {
	constructor() { super('Cancelled'); this.name = 'CancelledError'; }
}

// --------------------------------------------------------------------------- CRC-32 (zlib)
const CRC_TABLE = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();
export function crc32(u8) {
	let c = 0xffffffff;
	for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

// --------------------------------------------------------------------------- AES-128 / CMAC
// Key = AES-128-CMAC(secret, seed), as CSecurityAccess in the firmware
const SBOX = Uint8Array.from((
	'637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
	'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
	'09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
	'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
	'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
	'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
	'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
	'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16').match(/../g), (h) => parseInt(h, 16));
const xtime = (x) => ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;

function expandKey(key) {
	const w = new Uint8Array(176);
	w.set(key);
	let rcon = 1;
	for (let i = 16; i < 176; i += 4) {
		let t = w.slice(i - 4, i);
		if (i % 16 === 0) {
			t = Uint8Array.of(SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]);
			rcon = xtime(rcon);
		}
		for (let j = 0; j < 4; j++) w[i + j] = w[i - 16 + j] ^ t[j];
	}
	return w;
}

export function aes128Encrypt(key, block) {
	if (key.length !== 16 || block.length !== 16) throw new Error('AES-128: needs a 16 byte key and block');
	const rk = expandKey(key);
	let s = new Uint8Array(16);
	for (let i = 0; i < 16; i++) s[i] = block[i] ^ rk[i];
	for (let r = 1; r <= 10; r++) {
		const t = new Uint8Array(16);
		for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) t[c * 4 + row] = SBOX[s[((c + row) % 4) * 4 + row]];
		if (r !== 10) {
			for (let c = 0; c < 4; c++) {
				const a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3];
				const all = a0 ^ a1 ^ a2 ^ a3;
				t[c * 4] ^= all ^ xtime(a0 ^ a1);
				t[c * 4 + 1] ^= all ^ xtime(a1 ^ a2);
				t[c * 4 + 2] ^= all ^ xtime(a2 ^ a3);
				t[c * 4 + 3] ^= all ^ xtime(a3 ^ a0);
			}
		}
		for (let i = 0; i < 16; i++) t[i] ^= rk[r * 16 + i];
		s = t;
	}
	return s;
}

function shiftLeft1(b) {
	const out = new Uint8Array(16);
	for (let i = 0; i < 16; i++) out[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 0xff;
	if (b[0] & 0x80) out[15] ^= 0x87;
	return out;
}

export function aesCmac(key, msg) {
	const L = aes128Encrypt(key, new Uint8Array(16));
	const k1 = shiftLeft1(L), k2 = shiftLeft1(k1);
	const n = Math.max(1, Math.ceil(msg.length / 16));
	const complete = msg.length > 0 && msg.length % 16 === 0;
	let x = new Uint8Array(16);
	for (let i = 0; i < n - 1; i++) {
		const y = new Uint8Array(16);
		for (let j = 0; j < 16; j++) y[j] = x[j] ^ msg[i * 16 + j];
		x = aes128Encrypt(key, y);
	}
	const last = new Uint8Array(16);
	const rest = msg.subarray((n - 1) * 16);
	last.set(rest);
	if (!complete) last[rest.length] = 0x80;
	const k = complete ? k1 : k2;
	for (let j = 0; j < 16; j++) last[j] ^= k[j] ^ x[j];
	return aes128Encrypt(key, last);
}

export function parseKey(text) {
	const t = String(text || '').replace(/0x/gi, '').replace(/[\s,:]/g, '');
	if (!/^[0-9a-fA-F]{32}$/.test(t)) throw new Error('Key: exactly 32 hex characters (16 bytes)');
	return Uint8Array.from(t.match(/../g), (h) => parseInt(h, 16));
}

// --------------------------------------------------------------------------- Firmware files
/** Intel HEX -> { address, data } (gaps filled with 0xFF like erased flash) */
export function parseIntelHex(text) {
	const recs = [];
	let upper = 0, min = Infinity, max = -Infinity;
	const lines = text.split(/\r?\n/);
	for (let ln = 0; ln < lines.length; ln++) {
		const line = lines[ln].trim();
		if (!line) continue;
		if (line[0] !== ':' || line.length < 11) throw new Error(`HEX line ${ln + 1}: invalid`);
		const b = Uint8Array.from(line.slice(1).match(/../g), (h) => parseInt(h, 16));
		const len = b[0];
		if (b.length !== len + 5) throw new Error(`HEX line ${ln + 1}: length`);
		let sum = 0;
		for (const v of b) sum = (sum + v) & 0xff;
		if (sum !== 0) throw new Error(`HEX line ${ln + 1}: checksum`);
		const addr = (b[1] << 8) | b[2], type = b[3], data = b.subarray(4, 4 + len);
		if (type === 0x00) {
			const a = upper + addr;
			recs.push([a, data]);
			min = Math.min(min, a);
			max = Math.max(max, a + len);
		} else if (type === 0x01) {
			break;
		} else if (type === 0x02) {
			upper = ((data[0] << 8) | data[1]) << 4;
		} else if (type === 0x04) {
			upper = (((data[0] << 8) | data[1]) << 16) >>> 0;
		}
	}
	if (!recs.length) throw new Error('HEX file contains no data');
	const out = new Uint8Array(max - min).fill(0xff);
	for (const [a, d] of recs) out.set(d, a - min);
	return { address: min >>> 0, data: out };
}

/**
 * Header of an ESP32 app image (esp_image_header_t):
 *   0 magic 0xE9, 12..13 chip ID, 15..16 min. chip revision (full, e.g. 300 = v3.0), 17..18 max. chip revision
 */
export const ESP_CHIP_IDS = { 0: 'ESP32', 2: 'ESP32-S2', 5: 'ESP32-C3', 9: 'ESP32-S3', 12: 'ESP32-C2', 13: 'ESP32-C6', 16: 'ESP32-H2', 18: 'ESP32-P4' };
export function parseEspImage(u8) {
	if (u8.length < 24 || u8[0] !== 0xe9) return null;
	const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
	const chipId = dv.getUint16(12, true);
	const r = { chipId, chip: ESP_CHIP_IDS[chipId] || `Chip ${chipId}`, minRev: dv.getUint16(15, true), maxRev: dv.getUint16(17, true) };
	// esp_app_desc_t right after the first segment header (24 + 8): magic 0xABCD5432, version, project
	if (u8.length >= 32 + 256 && dv.getUint32(32, true) === 0xabcd5432) {
		const str = (o, n) => new TextDecoder().decode(u8.subarray(o, o + n)).replace(/\0.*$/s, '');
		r.appVersion = str(48, 32);
		r.project = str(80, 32);
		r.buildDate = `${str(128, 16)} ${str(112, 16)}`.trim();
	}
	return r;
}
/** Does the chip revision (full, e.g. 301) fit the image? 0xFFFF = no upper limit */
export function revMatches(info, rev) {
	if (!info || rev == null) return true;
	return rev >= info.minRev && (info.maxRev === 0xffff || info.maxRev === 0 || rev <= info.maxRev);
}
/**
 * Does a manifest product fit the chip and revision?
 * ESP32-P4: builds for revision < v3.0 carry no upper limit in the image header but do not run on
 * v3.x (different ROM/caches), so they are excluded here.
 */
export function buildFits(p, chip, rev) {
	if (chip && p.chip && p.chip !== chip) return false;
	const min = p.chipRev?.min ?? 0;
	if (!revMatches({ minRev: min, maxRev: p.chipRev?.max ?? 0xffff }, rev)) return false;
	if ((p.chip || chip) === 'ESP32-P4' && rev != null && rev >= 300 && min < 300) return false;
	return true;
}
export const fmtRev = (r) => `v${Math.floor(r / 100)}.${r % 100}`;

/**
 * Prepare and check a file for a UDS update.
 *   ESP (firmware.bin): address 0 = update partition (ota_0) of the UDS bootloader
 *   STM32 (.hex):       starts at 0x08008000, at most 164 KB
 */
export function prepareUpdateImage(type, fileName, bytes) {
	const t = DEVICE_TYPES[type];
	if (!t) throw new Error(`Unknown device type 0x${type.toString(16)}`);
	const name = (fileName || '').toLowerCase();
	if (t.image === 'esp') {
		if (!name.endsWith('.bin')) throw new Error('This device needs a firmware.bin');
		const info = parseEspImage(bytes);
		if (!info) throw new Error('Not an ESP32 application (file does not start with 0xE9)');
		if (t.chip && info.chip !== t.chip) throw new Error(`File is for ${info.chip}, the device is an ${t.chip}`);
		return { address: 0, data: bytes, info, sendCrc: true };
	}
	let img;
	if (name.endsWith('.hex')) img = parseIntelHex(new TextDecoder().decode(bytes));
	else if (name.endsWith('.bin')) img = { address: STM32_APP_ADDR, data: bytes };
	else throw new Error('The STM32 needs a .hex file');
	if (img.address !== STM32_APP_ADDR) {
		throw new Error(`The application must start at 0x${STM32_APP_ADDR.toString(16).toUpperCase()} (file: 0x${img.address.toString(16).toUpperCase()}). Does it contain the bootloader?`);
	}
	if (img.data.length > STM32_APP_MAX) throw new Error(`Application too large: ${(img.data.length / 1024).toFixed(1)} KB (max. 164 KB)`);
	return { ...img, info: null, sendCrc: false };
}

// --------------------------------------------------------------------------- SLCAN
const enc = new TextEncoder();
export function encodeSlcan(f) {
	const id = f.ext ? f.id.toString(16).toUpperCase().padStart(8, '0') : f.id.toString(16).toUpperCase().padStart(3, '0');
	return `${f.ext ? 'T' : 't'}${id}${f.data.length}${hex(f.data, '')}\r`;
}
export function decodeSlcan(line) {
	const c = line[0];
	if (c !== 't' && c !== 'T') return null;
	const ext = c === 'T', n = ext ? 8 : 3;
	if (line.length < 2 + n) return null;
	const id = parseInt(line.slice(1, 1 + n), 16), dlc = parseInt(line[1 + n], 16);
	if (!(dlc >= 0 && dlc <= 8) || line.length < 2 + n + dlc * 2 || Number.isNaN(id)) return null;
	const data = new Uint8Array(dlc);
	for (let i = 0; i < dlc; i++) data[i] = parseInt(line.substr(2 + n + i * 2, 2), 16);
	return { id: id >>> 0, ext, data };
}

/**
 * SLCAN over a byte stream.
 * stream: { write(Uint8Array): Promise, onData: (cb) => void }
 * The dongle acknowledges every frame with z/Z once it went out over the air (error: BEL).
 * At most `window` frames are unacknowledged, so ISO-TP bursts run at the pace of the radio link.
 */
export class SlcanLink {
	constructor(stream, { window = 8, ackTimeoutMs = 400 } = {}) {
		this.stream = stream;
		this.window = window;
		this.ackTimeoutMs = ackTimeoutMs;
		this.listeners = new Set();
		this.pending = [];          // outstanding acknowledgements [{resolve, t}]
		this.waiters = [];          // waiting for a free slot in the window
		this.line = '';
		this.stats = { tx: 0, rx: 0, txErr: 0, ackTimeout: 0 };
		this.trace = null;          // (dir, text) => void
		stream.onData((u8) => this._onBytes(u8));
		this._timer = setInterval(() => this._expireAcks(), 100);
	}

	close() { clearInterval(this._timer); }
	addListener(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

	async open() {
		// sync with empty lines, then close channel / set bitrate / open (the dongle only acknowledges)
		for (const cmd of ['\r\r\r', 'C\r', 'S6\r', 'O\r']) {
			await this.stream.write(enc.encode(cmd));
			await sleep(30);
		}
	}

	_onBytes(u8) {
		for (const b of u8) {
			if (b === 0x07) {                      // BEL: error for the last command
				this.line = '';
				this.stats.txErr++;
				this._ack(false);
			} else if (b === 0x0d) {
				this._onLine(this.line);
				this.line = '';
			} else if (b !== 0x0a) {
				this.line += String.fromCharCode(b);
				if (this.line.length > 64) this.line = '';
			}
		}
	}

	_onLine(line) {
		if (line === 'z' || line === 'Z') { this._ack(true); return; }
		const f = decodeSlcan(line);
		if (!f) return;
		this.stats.rx++;
		if (this.trace) this.trace('rx', line);
		for (const fn of this.listeners) {
			try { fn(f); } catch (e) { console.error(e); }
		}
	}

	_ack(ok) {
		const p = this.pending.shift();
		if (p) p.resolve(ok);
		this._release();
	}

	_expireAcks() {
		const now = Date.now();
		while (this.pending.length && now - this.pending[0].t > this.ackTimeoutMs) {
			this.stats.ackTimeout++;
			this.pending.shift().resolve(false);
		}
		this._release();
	}

	_release() {
		while (this.waiters.length && this.pending.length < this.window) this.waiters.shift()();
	}

	/**
	 * Send a frame. Returns once there is room in the window and the frame is written.
	 * Result { ack }: Promise<boolean> with the dongle's acknowledgement.
	 */
	async send(f) {
		while (this.pending.length >= this.window) await new Promise((r) => this.waiters.push(r));
		let resolve;
		const ack = new Promise((r) => { resolve = r; });
		this.pending.push({ resolve, t: Date.now() });
		const line = encodeSlcan(f);
		if (this.trace) this.trace('tx', line.trim());
		this.stats.tx++;
		await this.stream.write(enc.encode(line));
		return { ack };
	}

	/** wait until all sent frames are acknowledged */
	async drain(timeoutMs = 2000) {
		const end = Date.now() + timeoutMs;
		while (this.pending.length && Date.now() < end) await sleep(5);
	}
}

// --------------------------------------------------------------------------- ISO-TP
export class IsoTpError extends Error {}

export class IsoTp {
	constructor(link, txId, rxId, { timeoutMs = 2000, padding = 0x00, rxBlockSize = 0, stMinMs = 0 } = {}) {
		this.link = link;
		this.txId = txId >>> 0;
		this.rxId = rxId >>> 0;
		this.timeoutMs = timeoutMs;
		this.padding = padding;
		this.stMinMs = stMinMs;          // lower limit for the pause between our CFs
		this.rxBlockSize = rxBlockSize;   // receiving side (tests): FlowControl after every n CFs
		this.queue = [];
		this.waiter = null;
		this.rx = null;              // message being received
		this.messages = [];          // completely received messages
		this.msgWaiter = null;
		this.unsub = link.addListener((f) => this._onFrame(f));
	}

	close() { this.unsub(); }

	_frame(bytes) {
		const d = new Uint8Array(8).fill(this.padding);
		d.set(bytes);
		return { id: this.txId, ext: true, data: d };
	}

	_onFrame(f) {
		if (!f.ext || f.id !== this.rxId || f.data.length < 1) return;
		const d = f.data, pci = d[0] >> 4;
		if (pci === 3) {                                         // FlowControl for our transmission
			this.queue.push(d);
			if (this.waiter) { const w = this.waiter; this.waiter = null; w(); }
			return;
		}
		if (pci === 0) {                                         // Single Frame
			const len = d[0] & 0x0f;
			if (len >= 1 && len <= 7) this._deliver(d.slice(1, 1 + len));
			this.rx = null;
		} else if (pci === 1) {                                  // First Frame
			const len = ((d[0] & 0x0f) << 8) | d[1];
			this.rx = { len, buf: new Uint8Array(len), pos: 0, sn: 1, cnt: 0 };
			const n = Math.min(6, len);
			this.rx.buf.set(d.subarray(2, 2 + n));
			this.rx.pos = n;
			this.link.send(this._frame([0x30, this.rxBlockSize, 0x00]));   // CTS, no pause
		} else if (pci === 2 && this.rx) {                       // Consecutive Frame
			if ((d[0] & 0x0f) !== (this.rx.sn & 0x0f)) { this.rx = null; return; }
			this.rx.sn++;
			const n = Math.min(7, this.rx.len - this.rx.pos);
			this.rx.buf.set(d.subarray(1, 1 + n), this.rx.pos);
			this.rx.pos += n;
			if (this.rx.pos >= this.rx.len) { this._deliver(this.rx.buf); this.rx = null; return; }
			if (this.rxBlockSize && ++this.rx.cnt >= this.rxBlockSize) {
				this.rx.cnt = 0;
				this.link.send(this._frame([0x30, this.rxBlockSize, 0x00]));
			}
		}
	}

	_deliver(msg) {
		this.messages.push(msg);
		if (this.msgWaiter) { const w = this.msgWaiter; this.msgWaiter = null; w(); }
	}

	async _waitFc(timeoutMs) {
		const end = Date.now() + timeoutMs;
		while (!this.queue.length) {
			const left = end - Date.now();
			if (left <= 0) throw new IsoTpError('No FlowControl (N_Bs)');
			await new Promise((r) => { this.waiter = r; setTimeout(r, left); });
		}
		return this.queue.shift();
	}

	clearRx() { this.messages = []; this.rx = null; }

	async send(payload) {
		if (payload.length <= 7) {
			await this.link.send(this._frame([payload.length, ...payload]));
			return;
		}
		if (payload.length > 4095) throw new IsoTpError('Message too long');
		this.queue = [];
		await this.link.send(this._frame([0x10 | (payload.length >> 8), payload.length & 0xff, ...payload.subarray(0, 6)]));
		let pos = 6, sn = 1;
		while (pos < payload.length) {
			let fc = await this._waitFc(this.timeoutMs);
			while ((fc[0] & 0x0f) === 1) fc = await this._waitFc(this.timeoutMs);   // WAIT
			if ((fc[0] & 0x0f) === 2) throw new IsoTpError('Receiver overflow (FC OVFLW)');
			const bs = fc[1];
			const st = Math.max(fc[2] <= 0x7f ? fc[2] : 0, this.stMinMs);
			let sent = 0;
			while (pos < payload.length && (bs === 0 || sent < bs)) {
				await this.link.send(this._frame([0x20 | (sn & 0x0f), ...payload.subarray(pos, pos + 7)]));
				pos += 7; sn++; sent++;
				if (st) await sleep(st);
			}
		}
	}

	/** next complete message, null on timeout */
	async receive(timeoutMs) {
		const end = Date.now() + timeoutMs;
		while (!this.messages.length) {
			const left = end - Date.now();
			if (left <= 0) {
				// in the middle of a long message: wait a little longer
				if (this.rx && Date.now() - end < 1000) { await sleep(20); continue; }
				return null;
			}
			await new Promise((r) => { this.msgWaiter = r; setTimeout(r, left); });
		}
		return this.messages.shift();
	}
}

// --------------------------------------------------------------------------- UDS
export const NRC_TEXT = {
	0x10: 'general reject', 0x11: 'service not supported', 0x12: 'sub-function not supported',
	0x13: 'wrong length', 0x22: 'conditions not correct', 0x24: 'request sequence error', 0x31: 'out of range',
	0x33: 'security access denied', 0x35: 'invalid key', 0x36: 'too many attempts', 0x37: 'delay not expired',
	0x70: 'upload/download not accepted', 0x71: 'transfer suspended', 0x72: 'programming failure', 0x73: 'wrong block sequence counter',
	0x7e: 'not supported in this session', 0x7f: 'service not supported in this session',
};
export class UdsError extends Error {
	constructor(sid, nrc) {
		super(`NRC 0x${nrc.toString(16).padStart(2, '0').toUpperCase()} (${NRC_TEXT[nrc] || 'unknown'}) on 0x${sid.toString(16).toUpperCase()}`);
		this.sid = sid;
		this.nrc = nrc;
	}
}
export class UdsTimeout extends Error {}

export class UdsClient {
	constructor(isotp, { p2Ms = 2000, p2StarMs = 6000 } = {}) {
		this.tp = isotp;
		this.p2Ms = p2Ms;
		this.p2StarMs = p2StarMs;
	}

	/**
	 * Send a request and return the response (from the SID). accept(resp) can drop late answers to an
	 * earlier request (e.g. duplicate 76 acknowledgements).
	 */
	async request(req, { p2Ms = this.p2Ms, p2StarMs = this.p2StarMs, accept = null } = {}) {
		const r = req instanceof Uint8Array ? req : Uint8Array.from(req);
		const sid = r[0];
		this.tp.clearRx();
		await this.tp.send(r);
		let wait = p2Ms;
		for (;;) {
			const resp = await this.tp.receive(wait);
			if (!resp) throw new UdsTimeout(`No answer to 0x${sid.toString(16).toUpperCase()}`);
			if (resp[0] === 0x7f && resp[1] === sid) {
				if (resp[2] === 0x78) { wait = p2StarMs; continue; }   // responsePending
				throw new UdsError(sid, resp[2]);
			}
			if (resp[0] === sid + 0x40 && (!accept || accept(resp))) return resp;
		}
	}
}

// --------------------------------------------------------------------------- Device discovery
/**
 * Listens for heartbeats (0x1144F0TT|NN), the wheel variant (0x401 byte 4) and the dongle status (0x222).
 * Heartbeat byte 1 bit 4 = UDS bootloader active, bytes 4..6 = version.
 *
 * A device that was left in its bootloader by an aborted update is "pinned": it stays in the list
 * even while no heartbeat arrives, so the update can simply be started again.
 */
export class Discovery {
	constructor(link, onChange) {
		this.devices = new Map();      // `${type}:${nr}` -> {...}
		this.variant = null;
		this.dongle = null;            // {radioOk, wheelKnown, buttons, at}
		this.onChange = onChange || (() => {});
		this.unsub = link.addListener((f) => this._onFrame(f));
	}
	close() { this.unsub(); }

	_onFrame(f) {
		const now = Date.now();
		if (f.ext && (f.id & 0xfffff000) === HB_BASE && f.data.length >= 8) {
			const d = f.data, type = (f.id >> 8) & 0x0f, nr = f.id & 0xff;   // TT is 4 bits (as in the flash broadcast)
			const key = `${type}:${nr}`;
			const prev = this.devices.get(key);
			const dev = {
				type, nr, key,
				version: `${d[4]}.${d[5]}.${d[6]}`,
				bootloader: !!(d[1] & 0x10),
				state: d[7],
				seen: now,
				reqId: udsRequestId(type, nr),
				variant: prev?.variant ?? null,
				pinned: prev?.pinned && !!(d[1] & 0x10),   // pin ends once the application runs again
			};
			if (type === 0x05 || type === 0x06) dev.variant = this.variant ?? dev.variant;
			this.devices.set(key, dev);
			if (!prev || prev.version !== dev.version || prev.bootloader !== dev.bootloader || prev.variant !== dev.variant) this.onChange();
		} else if (!f.ext && f.id === 0x401 && f.data.length >= 5) {
			const v = f.data[4];
			if (v && v !== this.variant) {
				this.variant = v;
				for (const d of this.devices.values()) if (d.type === 0x05 || d.type === 0x06) d.variant = v;
				this.onChange();
			}
		} else if (!f.ext && f.id === 0x222 && f.data.length >= 1) {
			const b = f.data[0];
			const first = !this.dongle;
			this.dongle = { radioOk: !!(b & 1), wheelKnown: !!(b & 2), buttons: !!(b & 4), at: now };
			if (first) this.onChange();
		}
	}

	/** Mark a device as "left in the bootloader" so it stays listed without heartbeat. */
	pin(dev) {
		const prev = this.devices.get(dev.key) || {};
		this.devices.set(dev.key, { ...prev, ...dev, bootloader: true, pinned: true, seen: prev.seen ?? 0 });
		this.onChange();
	}

	/** Add a device that answered a TesterPresent probe but sends no heartbeat. */
	addProbed({ type, nr }) {
		const key = `${type}:${nr}`;
		const prev = this.devices.get(key);
		if (prev && Date.now() - prev.seen < HEARTBEAT_MAX_AGE_MS) return;
		this.devices.set(key, {
			version: '?', bootloader: false, variant: type === 5 || type === 6 ? this.variant : null,
			...prev, type, nr, key, reqId: udsRequestId(type, nr), seen: Date.now() + 30000, probed: true,
		});
		this.onChange();
	}

	/** Devices whose heartbeat arrived within maxAgeMs, plus pinned ones. */
	list(maxAgeMs = HEARTBEAT_MAX_AGE_MS) {
		const now = Date.now();
		return [...this.devices.values()]
			.filter((d) => d.pinned || now - d.seen <= maxAgeMs)
			.map((d) => ({ ...d, stale: now - d.seen > maxAgeMs }))
			.sort((a, b) => a.type - b.type || a.nr - b.nr);
	}

	waitFor(pred, timeoutMs) {
		return new Promise((resolve) => {
			const end = Date.now() + timeoutMs;
			const tick = () => {
				const hit = [...this.devices.values()].find(pred);
				if (hit) return resolve(hit);
				if (Date.now() > end) return resolve(null);
				setTimeout(tick, 100);
			};
			tick();
		});
	}
}
export const HEARTBEAT_MAX_AGE_MS = 5000;   // heartbeats come every second; a few may get lost over the air

// --------------------------------------------------------------------------- Flashing
export function parseMaxBlock(resp) {
	// resp = 74 <LFID> <maxNumberOfBlockLength>; per ISO 14229 the length includes SID + block counter
	const d = resp.subarray(1);
	const lfid = d[0] >> 4;
	let max;
	if (lfid >= 1 && lfid <= 4 && d.length >= 1 + lfid) {
		max = 0;
		for (let i = 0; i < lfid; i++) max = max * 256 + d[1 + i];
		max -= 2;
	} else if (d.length >= 2) {
		max = d[1];                // older FlexHub firmware: 74 00 F0 -> 240 byte payload
	} else {
		throw new Error(`Unknown RequestDownload response ${hex(resp)}`);
	}
	max = Math.min(max, 4093);
	max -= max % 8;
	if (max < 8) throw new Error(`Invalid block length ${hex(resp)}`);
	return max;
}

/**
 * Transfer settings, same values as the "Connection" profiles of the UDS tool.
 *   stMinMs       minimum pause between consecutive frames (the device's FlowControl may ask for more)
 *   maxBlock      cap for the TransferData payload (0 = what the device offers); smaller blocks mean
 *                 fewer frames per block, so a lost frame costs less
 *   interBlockMs  pause after each TransferData block
 *   blockRetries  repeats of a TransferData block without answer
 *   requestRetries repeats of other requests (session, seed/key, erase, check)
 *   p2Ms          wait for the first answer of a request
 *   isoTpTimeoutMs wait for FlowControl / the next consecutive frame (N_Bs / N_Cr)
 */
export const LINK_PROFILES = {
	wireless: {
		label: 'Wireless (robust)',
		stMinMs: 2, maxBlock: 256, interBlockMs: 5, blockRetries: 6, requestRetries: 4, p2Ms: 2000, isoTpTimeoutMs: 2000,
	},
	standard: {
		label: 'Standard (fast)',
		stMinMs: 0, maxBlock: 0, interBlockMs: 0, blockRetries: 4, requestRetries: 3, p2Ms: 1000, isoTpTimeoutMs: 1200,
	},
};
export const DEFAULT_FLASH_OPTS = {
	...LINK_PROFILES.wireless,
	reset: true,
	waitForAppMs: 20000,
};

/**
 * Flash a device via UDS.
 *   link:      SlcanLink
 *   dev:       {type, nr}
 *   image:     from prepareUpdateImage()
 *   key:       16 bytes (Uint8Array) or null
 *   progress:  (done, total, text) => void
 *   log:       (text) => void
 *   signal:    { cancelled: bool }
 *   discovery: optional; used to wait for the heartbeat of the new application
 *   opts:      overrides for DEFAULT_FLASH_OPTS (see LINK_PROFILES)
 * Throws on failure; err.inBootloader tells whether the device was left in its bootloader.
 */
export async function flashDevice({ link, dev, image, key, progress = () => {}, log = () => {}, signal = {}, discovery = null, opts = {} }) {
	const o = { ...DEFAULT_FLASH_OPTS, ...opts };
	const reqId = udsRequestId(dev.type, dev.nr);
	const tp = new IsoTp(link, reqId, reqId + RX_OFFSET, { timeoutMs: o.isoTpTimeoutMs, stMinMs: o.stMinMs });
	const uds = new UdsClient(tp, { p2Ms: o.p2Ms });
	const total = image.data.length;
	const check = () => { if (signal.cancelled) throw new CancelledError(); };
	const t0 = Date.now();
	const broadcast = async (v) => {
		const f = { id: flashBroadcastId(dev.type), ext: true, data: Uint8Array.of(v, 0, 0, 0, 0, 0, 0, 0) };
		for (let i = 0; i < 5; i++) { await link.send(f); await sleep(100); }
	};

	// Request with repeats on timeout / radio loss (not on a negative response)
	const req = async (what, bytes, ro = {}, tries = o.requestRetries) => {
		for (let i = 0; ; i++) {
			uds.lastAttempts = i + 1;
			try {
				return await uds.request(bytes, ro);
			} catch (e) {
				if (e instanceof UdsError || i + 1 >= tries) throw e;
				log(`${what}: ${e.message} – retrying`);
				await sleep(300);
				check();
			}
		}
	};

	log(`Target 0x${reqId.toString(16).toUpperCase()}, ${total} bytes, CRC-32 ${crc32(image.data).toString(16).toUpperCase().padStart(8, '0')}`);
	log(`Link: STmin ≥ ${o.stMinMs} ms, block ≤ ${o.maxBlock || 'device'} bytes, ${o.interBlockMs} ms between blocks, ${o.blockRetries} block retries`);
	let inBoot = !!dev.bootloader, downloading = false;
	try {
		progress(0, total, 'Announcing the update …');
		await broadcast(1);
		await sleep(700);
		check();

		// 10 02: the application answers 7F 10 78, restarts into the UDS bootloader, which then sends 50 02
		progress(0, total, 'Switching to the bootloader …');
		let ok = false;
		for (let i = 0; i < Math.max(3, o.requestRetries) && !ok; i++) {
			try {
				await uds.request([0x10, 0x02], { p2Ms: Math.max(3000, o.p2Ms), p2StarMs: 12000 });
				ok = true;
			} catch (e) {
				if (e instanceof UdsError) throw new Error(`Programming session rejected: ${e.message}`);
				log(`10 02: ${e.message} – retrying`);
				await sleep(1500);
				check();
			}
		}
		if (!ok) throw new Error('No answer to "10 02" (programming session). Is the wheel switched on and in range?');
		inBoot = true;
		log('Programming session active');
		check();

		// 27 01 / 27 02
		progress(0, total, 'Unlocking …');
		try {
			const seedResp = await req('27 01', [0x27, 0x01]);
			const seed = seedResp.subarray(2);
			if (seed.length && seed.some((b) => b !== 0)) {
				if (!key) throw new Error('The device needs a key (Settings → UDS key)');
				await req('27 02', Uint8Array.of(0x27, 0x02, ...aesCmac(key, seed)), {}, 1);
				log('Unlocked');
			} else {
				log('Already unlocked');
			}
		} catch (e) {
			if (e instanceof UdsError && (e.nrc === 0x11 || e.nrc === 0x12)) log('Device without seed/key – continuing');
			else if (e instanceof UdsError && e.nrc === 0x35) throw new Error('Wrong UDS key – the firmware on the device was built with a different key');
			else throw e;
		}
		check();

		// 34 00 44 <address> <size>: the device erases its update area
		progress(0, total, 'Erasing …');
		const req34 = new Uint8Array(11);
		req34.set([0x34, 0x00, 0x44]);
		new DataView(req34.buffer).setUint32(3, image.address >>> 0, false);
		new DataView(req34.buffer).setUint32(7, total, false);
		const r34 = await req('34', req34, { p2Ms: 20000, p2StarMs: 30000 });
		downloading = true;
		let block = parseMaxBlock(r34);
		if (o.maxBlock && o.maxBlock < block) block = Math.max(16, o.maxBlock - (o.maxBlock % 8));
		log(`Block size ${block} bytes`);

		// 36 …  After a loss the following blocks get smaller (fewer frames per block), later larger
		// again. A repeated block keeps its size: if the device had already written it (only the answer
		// was lost) it reports 0x73 and the transfer continues with the next block.
		const maxBlock = block;
		let cur = maxBlock, okRun = 0;
		let pos = 0, counter = 1, retries = 0, nr = 0;
		const tData = Date.now();
		while (pos < total) {
			check();
			nr++;
			const chunk = image.data.subarray(pos, pos + cur);
			const r36 = new Uint8Array(2 + chunk.length);
			r36[0] = 0x36; r36[1] = counter; r36.set(chunk, 2);
			const ctr = counter;
			let failed = false;
			for (let attempt = 0; ; attempt++) {
				try {
					await uds.request(r36, { p2Ms: o.p2Ms, p2StarMs: 10000, accept: (r) => r[1] === ctr });
					break;
				} catch (e) {
					if (e instanceof UdsError) {
						if (attempt > 0 && e.nrc === 0x73) { log(`Block ${nr}: had already arrived`); break; }
						throw new Error(`Block ${nr} (at byte ${pos}): ${e.message}`);
					}
					if (attempt >= o.blockRetries) throw new Error(`Block ${nr} (at byte ${pos}): no answer after ${attempt + 1} attempts – check the radio link`);
					retries++;
					failed = true;
					log(`Block ${nr}: ${e.message} – retry ${attempt + 1}/${o.blockRetries}`);
					await sleep(150);
					check();
				}
			}
			pos += chunk.length;
			counter = (counter + 1) & 0xff;
			if (failed) {
				okRun = 0;
				const smaller = Math.max(128, (cur >> 1) - ((cur >> 1) % 8));
				if (smaller < cur) { cur = smaller; log(`Blocks now ${cur} bytes`); }
			} else if (cur < maxBlock && ++okRun >= 8) {
				okRun = 0;
				cur = Math.min(maxBlock, cur * 2);
			}
			const rate = pos / Math.max(0.001, (Date.now() - tData) / 1000);
			progress(pos, total, `${Math.round(pos / 1024)} / ${Math.round(total / 1024)} KB · ${(rate / 1024).toFixed(1)} KB/s · ${Math.round((total - pos) / rate)} s left`);
			if (o.interBlockMs) await sleep(o.interBlockMs);
		}

		// 37 [CRC-32 big endian, ESP only]: verify and activate the new image
		progress(total, total, 'Verifying …');
		const req37 = image.sendCrc ? new Uint8Array(5) : Uint8Array.of(0x37);
		if (image.sendCrc) { req37[0] = 0x37; new DataView(req37.buffer).setUint32(1, crc32(image.data), false); }
		try {
			await req('37', req37, { p2Ms: 20000, p2StarMs: 30000 });
		} catch (e) {
			// after a repeat: the device had already accepted the image (only the answer was lost)
			if (!(e instanceof UdsError && e.nrc === 0x24 && uds.lastAttempts > 1)) throw e;
			log('37: image had already been accepted');
		}
		downloading = false;
		log(`Transferred in ${((Date.now() - t0) / 1000).toFixed(1)} s (${nr} blocks, ${retries} retries)`);

		if (o.reset) {
			progress(total, total, 'Restarting …');
			try { await uds.request([0x11, 0x01], { p2Ms: 1500 }); } catch (e) { log(`Restart not confirmed (${e.message})`); }
			inBoot = false;
		}
	} catch (e) {
		e.inBootloader = inBoot;
		if (inBoot && discovery) discovery.pin({ type: dev.type, nr: dev.nr, key: `${dev.type}:${dev.nr}`, reqId, version: dev.version });
		throw e;
	} finally {
		try { await broadcast(0); } catch (e) { /* port gone */ }
		tp.close();
		if (downloading) log('Stopped during the transfer: the device stays in its bootloader and can be flashed again.');
	}

	if (o.reset && discovery) {
		progress(total, total, 'Waiting for the new firmware …');
		const since = Date.now();
		const hit = await discovery.waitFor((d) => d.type === dev.type && d.nr === dev.nr && d.seen > since + 300 && !d.bootloader, o.waitForAppMs);
		if (hit) { log(`Running: version ${hit.version}`); return { version: hit.version }; }
		log('No heartbeat from the application – maybe still in the bootloader (image rejected?) or out of radio range.');
		return { version: null };
	}
	return { version: null };
}

/** TesterPresent to the usual addresses (finds devices that send no heartbeat). */
export async function probeDevices(link, types = [5, 6, 8], nrs = [1, 2, 3, 4], waitMs = 800) {
	const found = [];
	const want = new Set();
	for (const t of types) for (const n of nrs) want.add(udsRequestId(t, n) + RX_OFFSET);
	const unsub = link.addListener((f) => {
		if (f.ext && want.has(f.id) && f.data[1] === 0x7e) {
			const req = f.id - RX_OFFSET;
			found.push({ type: (req >> 8) & 0x0f, nr: req & 0xff });
			want.delete(f.id);
		}
	});
	for (const t of types) for (const n of nrs) {
		await link.send({ id: udsRequestId(t, n), ext: true, data: Uint8Array.of(0x02, 0x3e, 0x00, 0, 0, 0, 0, 0) });
	}
	await sleep(waitMs);
	unsub();
	return found;
}
