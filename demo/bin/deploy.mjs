/**
 * After the stack is up: deploy the attestor and the trusted-issuer registry
 * when this FireFly does not already have them, trust the generated issuer,
 * then ask the issuer for a fresh credential offer.
 *
 * Talks to FireFly and the issuer by their Compose names. Run it with
 * `docker compose run` on the demo network, not from the host.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

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

const MEMBER_VCT = 'http://issuer.demo/openid4vci/member';

function contractArtifact(contractName) {
	const raw = strip(readFileSync(`${runtime}/contract.json`, 'utf8'));
	const parsed = JSON.parse(raw);
	const contracts = parsed.contracts || {};
	const key = Object.keys(contracts).find((name) => name.endsWith(`:${contractName}`));
	if (!key) {
		throw new Error(`solc output has no ${contractName}`);
	}
	const artifact = contracts[key];
	const abi = typeof artifact.abi === 'string' ? JSON.parse(artifact.abi) : artifact.abi;
	const bin = String(artifact.bin || '').replace(/^0x/, '');
	if (!abi || !bin) {
		throw new Error(`solc output is missing the ABI or bytecode for ${contractName}`);
	}
	return { abi, bytecode: `0x${bin}` };
}

async function getApi(name, attempts = 10) {
	try {
		return await call(ns(`apis/${name}`), {}, attempts);
	} catch (error) {
		if (error.status === 404) {
			return null;
		}
		throw error;
	}
}

async function deployContract(contractName, signer, input) {
	const { abi, bytecode } = contractArtifact(contractName);
	const deployed = await call(`${ns('contracts/deploy')}?confirm=true`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			contract: bytecode,
			definition: abi,
			input,
			key: signer,
		}),
	}, 60);
	const address = deployed?.output?.contractLocation?.address;
	if (!address) {
		throw new Error(`deploy of ${contractName} did not return a contract address: ${JSON.stringify(deployed)}`);
	}
	return address;
}

async function interfaceId(contractName) {
	const { abi } = contractArtifact(contractName);
	let ffi = await call(ns('contracts/interfaces/generate'), {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			name: contractName,
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
		const found = (Array.isArray(list) ? list : []).find((item) => item.name === contractName);
		if (!found) {
			throw error;
		}
		ffi = found;
	}
	if (!ffi.id) {
		throw new Error(`FireFly did not return an interface id for ${contractName}`);
	}
	return ffi.id;
}

/**
 * Publishes the API, or returns the address of the API that already has this
 * name. A second contract must not replace that address: the listener and
 * WordPress stay pointed at the first one.
 */
async function publishApi(name, contractName, address) {
	const id = await interfaceId(contractName);
	try {
		await call(`${ns('apis')}?confirm=true`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				name,
				interface: { id },
				location: { address },
			}),
		});
		return { address, interfaceId: id };
	} catch (error) {
		if (error.status !== 409) {
			throw error;
		}
		const current = await getApi(name, 5);
		const existing = current?.location?.address;
		if (!existing) {
			throw error;
		}
		return { address: existing, interfaceId: current.interface?.id || id };
	}
}

function loginListener(listeners) {
	return (Array.isArray(listeners) ? listeners : []).find((item) => item.event === 'LoginAttested' || item.name === 'LoginAttested');
}

async function ensureListener() {
	const listed = await call(ns('apis/ssi-login-attestor/listeners'), {}, 10);
	const found = loginListener(listed);
	if (found?.id) {
		return found.id;
	}
	try {
		const created = await call(`${ns('apis/ssi-login-attestor/listeners/LoginAttested')}?confirm=true`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ topic: 'ssi-login', options: { firstEvent: 'newest' } }),
		});
		if (!created?.id) {
			throw new Error('FireFly did not return a listener id');
		}
		return created.id;
	} catch (error) {
		if (error.status !== 409) {
			throw error;
		}
		const again = loginListener(await call(ns('apis/ssi-login-attestor/listeners')));
		if (!again?.id) {
			throw error;
		}
		return again.id;
	}
}

/**
 * The attestor is deployed by the bridge's signing key, which becomes its
 * first verifier. The registry is deployed by a different key, which becomes
 * its owner, and only that key is allowed to call setIssuer.
 *
 * @param {string} signer
 * @param {string} owner
 */
export function demoSigningPlan(signer, owner) {
	if (typeof signer !== 'string' || typeof owner !== 'string') {
		throw new Error('missing signing key');
	}
	const attest = signer.trim();
	const registryOwner = owner.trim();
	if (attest === '' || registryOwner === '') {
		throw new Error('missing signing key');
	}
	if (attest.toLowerCase() === registryOwner.toLowerCase()) {
		throw new Error('registry owner must not be the bridge signing key');
	}
	return {
		attestor: { key: attest, input: [attest] },
		registry: { key: registryOwner, input: [] },
		setIssuer(did, vct) {
			return {
				key: registryOwner,
				input: { issuer: did, vct, trusted: true },
			};
		},
	};
}

async function attestor(plan) {
	const api = await getApi('ssi-login-attestor', 60);
	let address = api?.location?.address || '';
	let publishedInterface = api?.interface?.id || '';
	if (!address) {
		process.stdout.write('deploying the attestor\n');
		address = await deployContract('SsiLoginAttestor', plan.attestor.key, plan.attestor.input);
		const published = await publishApi('ssi-login-attestor', 'SsiLoginAttestor', address);
		address = published.address;
		publishedInterface = published.interfaceId;
	}
	const listenerId = await ensureListener();
	return { address, interfaceId: publishedInterface, listenerId, signer: plan.attestor.key };
}

async function registry(plan, did) {
	const api = await getApi('trusted-issuer-registry', 10);
	let address = api?.location?.address || '';
	if (!address) {
		process.stdout.write('deploying the trusted-issuer registry\n');
		address = await deployContract('TrustedIssuerRegistry', plan.registry.key, plan.registry.input);
		address = (await publishApi('trusted-issuer-registry', 'TrustedIssuerRegistry', address)).address;
	}
	await call(`${ns('apis/trusted-issuer-registry/invoke/setIssuer')}?confirm=true`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(plan.setIssuer(did, MEMBER_VCT)),
	}, 30);
	process.stdout.write(`registry ${address}\n`);
	return address;
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

async function main() {
	const plan = demoSigningPlan(readRuntime('signer.address'), readRuntime('registry-owner.address'));
	const did = readRuntime('issuer.did');
	const deployment = await attestor(plan);
	deployment.registryAddress = await registry(plan, did);
	deployment.registryOwner = plan.registry.key;
	deployment.registryApi = 'trusted-issuer-registry';
	writeFileSync(`${runtime}/deployment.json`, `${JSON.stringify(deployment, null, 2)}\n`);
	process.stdout.write(`attestor ${deployment.address}\n`);
	const url = await offer();
	process.stdout.write(`offer ${url}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	await main();
}
