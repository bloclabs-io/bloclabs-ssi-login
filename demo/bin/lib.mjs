/**
 * Demo helpers with no dependencies: Keccak-256, RLP, an Ethereum address,
 * a did:jwk and a PBKDF2 keystore the FireFly signer can open.
 *
 * The issuer key and the chain key are produced here, on first start, and
 * written under demo/runtime/. Nothing in this file is a committed secret.
 */

import { createCipheriv, createPrivateKey, createPublicKey, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const MASK = (1n << 64n) - 1n;

// Keccak round constants. Keccak-256, not NIST SHA3: the padding byte is 0x01.
const RC = [
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
	0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
	0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
	0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
	0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
	0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// r[x][y], the Keccak rotation offsets.
const ROT = [
	[0, 36, 3, 41, 18],
	[1, 44, 10, 45, 2],
	[62, 6, 43, 15, 61],
	[28, 55, 25, 21, 56],
	[27, 20, 39, 8, 14],
];

function rotl(value, bits) {
	const shift = BigInt(bits % 64);
	if (shift === 0n) {
		return value;
	}
	return ((value << shift) | (value >> (64n - shift))) & MASK;
}

function keccakF(state) {
	for (let round = 0; round < 24; round += 1) {
		const column = [0n, 0n, 0n, 0n, 0n];
		for (let x = 0; x < 5; x += 1) {
			column[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
		}
		for (let x = 0; x < 5; x += 1) {
			const mixed = column[(x + 4) % 5] ^ rotl(column[(x + 1) % 5], 1);
			for (let y = 0; y < 5; y += 1) {
				state[x][y] = (state[x][y] ^ mixed) & MASK;
			}
		}
		const next = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
		for (let x = 0; x < 5; x += 1) {
			for (let y = 0; y < 5; y += 1) {
				next[y][(2 * x + 3 * y) % 5] = rotl(state[x][y], ROT[x][y]);
			}
		}
		for (let x = 0; x < 5; x += 1) {
			for (let y = 0; y < 5; y += 1) {
				const value = next[x][y] ^ ((~next[(x + 1) % 5][y]) & next[(x + 2) % 5][y]);
				state[x][y] = value & MASK;
			}
		}
		state[0][0] = (state[0][0] ^ RC[round]) & MASK;
	}
}

/**
 * @param {Buffer | Uint8Array | string} message
 * @returns {Buffer} 32 bytes
 */
export function keccak256(message) {
	const input = Buffer.isBuffer(message) ? message : Buffer.from(message);
	const rate = 136;
	const padded = Buffer.alloc(Math.max(rate, Math.ceil((input.length + 1) / rate) * rate));
	input.copy(padded);
	padded[input.length] ^= 0x01;
	padded[padded.length - 1] ^= 0x80;

	const state = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
	for (let offset = 0; offset < padded.length; offset += rate) {
		for (let lane = 0; lane < 17; lane += 1) {
			const at = offset + lane * 8;
			let value = 0n;
			for (let byte = 0; byte < 8; byte += 1) {
				value |= BigInt(padded[at + byte]) << BigInt(8 * byte);
			}
			state[lane % 5][Math.floor(lane / 5)] ^= value;
		}
		keccakF(state);
	}
	const out = Buffer.alloc(32);
	for (let index = 0; index < 4; index += 1) {
		let value = state[index % 5][Math.floor(index / 5)];
		for (let byte = 0; byte < 8; byte += 1) {
			out[index * 8 + byte] = Number(value & 0xffn);
			value >>= 8n;
		}
	}
	return out;
}

function rlpLength(length, offset) {
	if (length < 56) {
		return Buffer.from([offset + length]);
	}
	const hex = length.toString(16);
	const body = Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, 'hex');
	return Buffer.concat([Buffer.from([offset + 55 + body.length]), body]);
}

/**
 * @param {Buffer | Buffer[] | unknown[]} item
 * @returns {Buffer}
 */
export function rlpEncode(item) {
	if (Array.isArray(item)) {
		const payload = Buffer.concat(item.map((entry) => rlpEncode(entry)));
		return Buffer.concat([rlpLength(payload.length, 0xc0), payload]);
	}
	const bytes = Buffer.isBuffer(item) ? item : Buffer.from(item);
	if (bytes.length === 1 && bytes[0] < 0x80) {
		return bytes;
	}
	return Buffer.concat([rlpLength(bytes.length, 0x80), bytes]);
}

/**
 * QBFT genesis extraData: 32 zero vanity bytes, the validator, no vote,
 * round 0 and no seals. Besu rejects a genesis whose validator is not this node.
 *
 * @param {Buffer} address 20 bytes
 * @returns {string} 0x-prefixed hex
 */
export function qbftExtraData(address) {
	if (address.length !== 20) {
		throw new Error('validator address must be 20 bytes');
	}
	const encoded = rlpEncode([
		Buffer.alloc(32),
		[address],
		[],
		Buffer.alloc(0),
		[],
	]);
	return `0x${encoded.toString('hex')}`;
}

export function bytesToHex(bytes) {
	return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex) {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	return Buffer.from(clean.length % 2 === 0 ? clean : `0${clean}`, 'hex');
}

export function base64UrlEncode(bytes) {
	return Buffer.from(bytes).toString('base64url');
}

export function base64UrlDecode(text) {
	const pad = text.length % 4 === 0 ? '' : '='.repeat(4 - (text.length % 4));
	return Buffer.from(text + pad, 'base64url');
}

function leftPad(bytes, size) {
	if (bytes.length > size) {
		throw new Error(`value is ${bytes.length} bytes, expected at most ${size}`);
	}
	if (bytes.length === size) {
		return bytes;
	}
	return Buffer.concat([Buffer.alloc(size - bytes.length), bytes]);
}

/**
 * @param {string} x base64url
 * @param {string} y base64url
 * @returns {string} 0x-prefixed address
 */
export function ethereumAddress(x, y) {
	const hash = keccak256(Buffer.concat([
		leftPad(base64UrlDecode(x), 32),
		leftPad(base64UrlDecode(y), 32),
	]));
	return `0x${hash.subarray(12).toString('hex')}`;
}

/**
 * did:jwk for a P-256 public key, in the member order walt.id puts in `iss`
 * (kty, crv, x, y). The verifier resolves whatever string the issuer embeds,
 * so the demo writes this exact value into the issuer config.
 *
 * @param {string} x
 * @param {string} y
 */
export function didJwkP256(x, y) {
	const json = JSON.stringify({ kty: 'EC', crv: 'P-256', x, y });
	return `did:jwk:${base64UrlEncode(Buffer.from(json))}`;
}

/**
 * @param {'P-256' | 'secp256k1'} curve
 */
export function generateEcKey(curve) {
	const named = curve === 'P-256' ? 'prime256v1' : 'secp256k1';
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: named });
	const jwk = privateKey.export({ format: 'jwk' });
	return {
		kty: 'EC',
		crv: curve === 'P-256' ? 'P-256' : 'secp256k1',
		d: jwk.d,
		x: jwk.x,
		y: jwk.y,
	};
}

/**
 * 32-byte secp256k1 scalar from a JWK `d`, left-padded. Besu's node key file
 * is this value in hex.
 *
 * @param {string} d
 */
export function scalarHex(d) {
	return leftPad(base64UrlDecode(d), 32).toString('hex');
}

/**
 * Ethereum keystore v3 (PBKDF2, AES-128-CTR) for one secp256k1 key.
 * The MAC is Keccak-256 of the last 16 derived bytes and the ciphertext,
 * which is what firefly-signer checks.
 *
 * @param {{ d: string, x: string, y: string }} jwk
 * @param {string} password
 */
export function keystoreV3(jwk, password) {
	const secret = leftPad(base64UrlDecode(jwk.d), 32);
	const salt = randomBytes(32);
	const iv = randomBytes(16);
	const iterations = 16384;
	const derived = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
	const cipher = createCipheriv('aes-128-ctr', derived.subarray(0, 16), iv);
	const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
	const mac = keccak256(Buffer.concat([derived.subarray(16, 32), ciphertext]));
	return {
		version: 3,
		id: randomUUID(),
		address: ethereumAddress(jwk.x, jwk.y).slice(2),
		crypto: {
			ciphertext: ciphertext.toString('hex'),
			cipherparams: { iv: iv.toString('hex') },
			cipher: 'aes-128-ctr',
			kdf: 'pbkdf2',
			kdfparams: {
				dklen: 32,
				c: iterations,
				prf: 'hmac-sha256',
				salt: salt.toString('hex'),
			},
			mac: mac.toString('hex'),
		},
	};
}

/**
 * Open a keystore produced by keystoreV3. Used by the self-test so a bad MAC
 * fails here rather than when FireFly tries to sign.
 *
 * @param {ReturnType<typeof keystoreV3>} file
 * @param {string} password
 */
export function openKeystore(file, password) {
	const crypto = file.crypto;
	const derived = pbkdf2Sync(
		password,
		hexToBytes(crypto.kdfparams.salt),
		crypto.kdfparams.c,
		crypto.kdfparams.dklen,
		'sha256',
	);
	const ciphertext = hexToBytes(crypto.ciphertext);
	const mac = keccak256(Buffer.concat([derived.subarray(16, 32), ciphertext]));
	if (mac.toString('hex') !== crypto.mac) {
		throw new Error('keystore MAC does not match');
	}
	const decipher = createCipheriv('aes-128-ctr', derived.subarray(0, 16), hexToBytes(crypto.cipherparams.iv));
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Known-answer checks for the pieces the chain and the issuer depend on.
 * `node demo/bin/lib.mjs` runs them.
 */
export function selfTest() {
	const empty = keccak256(Buffer.alloc(0)).toString('hex');
	if (empty !== 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470') {
		throw new Error(`keccak256("") = ${empty}`);
	}
	const abc = keccak256(Buffer.from('abc')).toString('hex');
	if (abc !== '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45') {
		throw new Error(`keccak256("abc") = ${abc}`);
	}

	const x = base64UrlEncode(hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
	const y = base64UrlEncode(hexToBytes('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'));
	const address = ethereumAddress(x, y);
	if (address !== '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf') {
		throw new Error(`address of key 1 = ${address}`);
	}

	const d = base64UrlEncode(leftPad(Buffer.from([1]), 32));
	const imported = createPrivateKey({ key: { kty: 'EC', crv: 'secp256k1', d, x, y }, format: 'jwk' });
	const exported = createPublicKey(imported).export({ format: 'jwk' });
	if (exported.x !== x || exported.y !== y) {
		throw new Error('node rejected the secp256k1 test key');
	}

	const extra = qbftExtraData(hexToBytes(address));
	const repeated = Buffer.alloc(20, 0x01);
	const sample = qbftExtraData(repeated);
	const expected = 'f83aa00000000000000000000000000000000000000000000000000000000000000000d5940101010101010101010101010101010101010101c080c0';
	if (sample !== `0x${expected}`) {
		throw new Error(`qbft extraData = ${sample}`);
	}
	if (!extra.startsWith('0xf8')) {
		throw new Error(`unexpected extraData prefix ${extra.slice(0, 6)}`);
	}

	const password = 'demo-password';
	const stored = keystoreV3({ d, x, y, kty: 'EC', crv: 'secp256k1' }, password);
	const opened = openKeystore(stored, password);
	if (!opened.equals(leftPad(Buffer.from([1]), 32))) {
		throw new Error('keystore round trip changed the scalar');
	}
	let rejected = false;
	try {
		openKeystore(stored, 'wrong');
	} catch (error) {
		rejected = String(error.message).includes('MAC');
	}
	if (!rejected) {
		throw new Error('keystore accepted the wrong password');
	}

	const p256 = generateEcKey('P-256');
	const did = didJwkP256(p256.x, p256.y);
	const payload = JSON.parse(Buffer.from(base64UrlDecode(did.slice('did:jwk:'.length))).toString());
	if (payload.x !== p256.x || payload.y !== p256.y || payload.d) {
		throw new Error('did:jwk did not round-trip the public key');
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	selfTest();
	process.stdout.write('ok\n');
}
