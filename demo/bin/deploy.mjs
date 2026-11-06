/**
 * After the stack is up: deploy the attestor if this FireFly has none,
 * then ask the issuer for a fresh credential offer.
 *
 * Talks to FireFly and the issuer by their Compose names. Run it with
 * `docker compose run` on the demo network, not from the host.
 */

import { readFileSync, writeFileSync } from 'node:fs';

const root = (process.env.FIREFLY_URL || 'http://firefly:5000').replace(/\/$/, '');
const issuer = (process.env.ISSUER_URL || 'http://issuer.demo').replace(/\/$/, '');
const runtime = process.env.DEMO_RUNTIME || '/runtime';
const namespace = 'default';

function strip(text) {
	return text.replace(/\r/g, '').trim();
}

function readRuntime(name) {
	return strip(readFileSync(`${runtime}/${name}`, 'utf8'));
}

async function call(url, options = {}, attempts = 30) {
	let last = 'no response';
	for (let attempt = 1; attempt <= attempts; attempt += 1) {
		try {
			const response = await fetch(url, {
				...options,
				headers: { accept: 'application/json', ...(options.headers || {}) },
				signal: AbortSignal.timeout(120000),
			});
			const text = await response.text();
			let body = null;
			if (text) {
				try {
					body = JSON.parse(text);
				} catch {
					body = text;
				}
			}
			if (response.ok) {
				return body;
			}
			last = `${response.status} ${typeof body === 'string' ? body : JSON.stringify(body)}`;
			if (response.status < 500) {
				const error = new Error(last);
				error.status = response.status;
				error.body = body;
				throw error;
			}
		} catch (error) {
			if (error.status) {
				throw error;
			}
			last = error.message;
		}
		await new Promise((resolve) => setTimeout(resolve, 2000));
	}
	throw new Error(`${url} failed: ${last}`);
}

function ns(path) {
	return `${root}/api/v1/namespaces/${namespace}/${path}`;
}

function contractArtifact() {
	const raw = strip(readFileSync(`${runtime}/contract.json`, 'utf8'));
	const parsed = JSON.parse(raw);
	const contracts = parsed.contracts || {};
	const key = Object.keys(contracts).find((name) => name.endsWith(':SsiLoginAttestor'));
	if (!key) {
		throw new Error('solc output has no SsiLoginAttestor');
	}
	const artifact = contracts[key];
	const abi = typeof artifact.abi === 'string' ? JSON.parse(artifact.abi) : artifact.abi;
	const bin = String(artifact.bin || '').replace(/^0x/, '');
	if (!abi || !bin) {
		throw new Error('solc output is missing the ABI or bytecode');
	}
	return { abi, bytecode: `0x${bin}` };
}

async function deployContract(signer) {
	const { abi, bytecode } = contractArtifact();
	const deployed = await call(`${ns('contracts/deploy')}?confirm=true`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			contract: bytecode,
			definition: abi,
			input: [signer],
			key: signer,
		}),
	}, 60);
	const address = deployed?.output?.contractLocation?.address;
	if (!address) {
		throw new Error(`deploy did not return a contract address: ${JSON.stringify(deployed)}`);
	}
	return address;
}

async function publish(signer, address) {
	const { abi } = contractArtifact();
	let ffi = await call(ns('contracts/interfaces/generate'), {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			name: 'SsiLoginAttestor',
			version: '1.0',
			input: { abi },
		}),
	});
	try {
		ffi = await call(`${ns('contracts/interfaces')}?confirm=true`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(ffi),
		});
	} catch (error) {
		if (error.status !== 409) {
			throw error;
		}
		const list = await call(ns('contracts/interfaces'));
		const found = (Array.isArray(list) ? list : []).find((item) => item.name === 'SsiLoginAttestor');
		if (!found) {
			throw error;
		}
		ffi = found;
	}
	if (!ffi.id) {
		throw new Error('FireFly did not return an interface id');
	}
	try {
		await call(`${ns('apis')}?confirm=true`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				name: 'ssi-login-attestor',
				interface: { id: ffi.id },
				location: { address },
			}),
		});
	} catch (error) {
		if (error.status !== 409) {
			throw error;
		}
	}
	let listener;
	try {
		listener = await call(`${ns('apis/ssi-login-attestor/listeners/LoginAttested')}?confirm=true`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ topic: 'ssi-login', options: { firstEvent: 'newest' } }),
		});
	} catch (error) {
		if (error.status !== 409) {
			throw error;
		}
		const listeners = await call(ns('apis/ssi-login-attestor/listeners'));
		listener = (Array.isArray(listeners) ? listeners : []).find((item) => item.event === 'LoginAttested' || item.name === 'LoginAttested');
	}
	if (!listener?.id) {
		throw new Error('FireFly did not return a listener id');
	}
	return { address, interfaceId: ffi.id, listenerId: listener.id, signer };
}

async function existing() {
	try {
		const api = await call(ns('apis/ssi-login-attestor'), {}, 60);
		const address = api?.location?.address;
		const listeners = await call(ns('apis/ssi-login-attestor/listeners'), {}, 10);
		const listener = (Array.isArray(listeners) ? listeners : []).find((item) => item.event === 'LoginAttested' || item.name === 'LoginAttested');
		if (address && listener?.id) {
			return {
				address,
				interfaceId: api.interface?.id || '',
				listenerId: listener.id,
				signer: readRuntime('signer.address'),
			};
		}
	} catch (error) {
		if (error.status && error.status !== 404) {
			throw error;
		}
	}
	return null;
}

async function offer() {
	const created = await call(`${issuer}/issuer2/credential-offers`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			profileId: 'member',
			authMethod: 'PRE_AUTHORIZED',
			expiresInSeconds: 86400,
		}),
	}, 90);
	const url = created?.credentialOffer;
	if (typeof url !== 'string' || url.length === 0) {
		throw new Error(`issuer did not return a credential offer: ${JSON.stringify(created)}`);
	}
	writeFileSync(`${runtime}/offer.url`, `${url}\n`);
	return url;
}

const signer = readRuntime('signer.address');
let deployment = await existing();
if (!deployment) {
	process.stdout.write('deploying the attestor\n');
	const address = await deployContract(signer);
	deployment = await publish(signer, address);
	writeFileSync(`${runtime}/deployment.json`, `${JSON.stringify(deployment, null, 2)}\n`);
	process.stdout.write(`attestor ${deployment.address}\n`);
} else {
	writeFileSync(`${runtime}/deployment.json`, `${JSON.stringify(deployment, null, 2)}\n`);
	process.stdout.write(`attestor already deployed at ${deployment.address}\n`);
}
const url = await offer();
process.stdout.write(`offer ${url}\n`);
