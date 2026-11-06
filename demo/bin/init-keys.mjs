/**
 * First start of the demo stack. Generates the issuer key, the chain keys and
 * the passwords, then exits. A later start finds runtime/ready and leaves
 * them alone, so the chain and the wallet keep the same keys.
 *
 * The registry owner is a different key from the one the bridge uses to
 * attest. Its keystore is written outside the signer directory.
 *
 * Secrets are written with Unix newlines. setup.sh still strips a carriage
 * return when it reads them back, because a Windows checkout or editor can
 * put one on a file that was generated here.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';

import {
	didJwkP256,
	ethereumAddress,
	generateEcKey,
	hexToBytes,
	keystoreV3,
	openKeystore,
	qbftExtraData,
	scalarHex,
	selfTest,
} from './lib.mjs';

const runtime = process.env.DEMO_RUNTIME || '/runtime';
const signerRoot = process.env.DEMO_SIGNER || '/signer';
const ownerRoot = process.env.DEMO_REGISTRY_OWNER || '/registry-owner';

function writeAt(root, name, contents) {
	if (contents.includes('\r')) {
		throw new Error(`${name} contains a carriage return`);
	}
	const path = join(root, name);
	mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
	chmodSync(dirname(path), 0o755);
	const data = contents.endsWith('\n') || !contents.includes('\n') ? contents : `${contents}\n`;
	writeFileSync(path, data, { mode: 0o644 });
	chmodSync(path, 0o644);
}

function write(name, contents) {
	writeAt(runtime, name, contents);
}

function secret() {
	return randomBytes(32).toString('hex');
}

function hoconJwk(jwk) {
	return `{
  type = "jwk"
  jwk = {
    kty = "EC"
    crv = "${jwk.crv}"
    d = "${jwk.d}"
    x = "${jwk.x}"
    y = "${jwk.y}"
  }
}`;
}

function jsonJwk(jwk) {
	return JSON.stringify({
		type: 'jwk',
		jwk: { kty: 'EC', crv: jwk.crv, d: jwk.d, x: jwk.x, y: jwk.y },
	});
}

function genesis(nodeAddress, fundAddresses) {
	return {
		config: {
			chainId: 1337,
			homesteadBlock: 0,
			eip150Block: 0,
			eip155Block: 0,
			eip158Block: 0,
			byzantiumBlock: 0,
			constantinopleBlock: 0,
			petersburgBlock: 0,
			istanbulBlock: 0,
			muirGlacierBlock: 0,
			berlinBlock: 0,
			londonBlock: 0,
			arrowGlacierBlock: 0,
			grayGlacierBlock: 0,
			// Paris, and no shanghaiTime: the attestor is compiled for Paris
			// because this chain rejects PUSH0.
			mergeNetsplitBlock: 0,
			zeroBaseFee: true,
			qbft: {
				blockperiodseconds: 2,
				epochlength: 30000,
				requesttimeoutseconds: 10,
				emptyblockperiodseconds: 2,
			},
		},
		nonce: '0x0',
		timestamp: '0x0',
		extraData: qbftExtraData(hexToBytes(nodeAddress)),
		gasLimit: '0x1fffffffffffff',
		difficulty: '0x1',
		mixHash: '0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365',
		coinbase: '0x0000000000000000000000000000000000000000',
		alloc: Object.fromEntries(fundAddresses.map((address) => [address.slice(2), {
			balance: '0x200000000000000000000000000000000000000000000000000000000000000',
		}])),
		baseFeePerGas: '0x0',
		number: '0x0',
		gasUsed: '0x0',
		parentHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
	};
}

function fireflyConfig(dbPassword, signer) {
	return `log:
  level: info
http:
  address: 0.0.0.0
  port: 5000
  publicURL: http://firefly:5000
ui:
  path: ./frontend
plugins:
  database:
    - name: database0
      type: postgres
      postgres:
        url: postgres://firefly:${dbPassword}@postgres:5432/firefly?sslmode=disable
        migrations:
          auto: true
  blockchain:
    - name: blockchain0
      type: ethereum
      ethereum:
        ethconnect:
          url: http://evmconnect:5008
          topic: "0"
namespaces:
  default: default
  predefined:
    - name: default
      description: blocLabs SSI login demo
      defaultKey: "${signer}"
      plugins: [database0, blockchain0]
      multiparty:
        enabled: false
`;
}

function evmconnectConfig() {
	return `log:
  level: info
api:
  port: 5008
  address: 0.0.0.0
  publicURL: http://evmconnect:5008
connector:
  url: http://ethsigner:8545
persistence:
  leveldb:
    path: /evmconnect/data/leveldb
ffcore:
  url: http://firefly:5000
  namespaces:
    - default
confirmations:
  required: 0
policyengine.simple:
  fixedGasPrice: 0
  gasOracle:
    mode: fixed
`;
}

function signerConfig() {
	return `server:
  port: 8545
  address: 0.0.0.0
backend:
  url: http://besu:8545
  chainId: 1337
fileWallet:
  path: /data/keystore
  filenames:
    primaryExt: .toml
  metadata:
    keyFileProperty: '{{ index .signing "key-file" }}'
    passwordFileProperty: '{{ index .signing "password-file" }}'
log:
  level: info
`;
}

function bridgeQueries(did) {
	return `${JSON.stringify({
		default: {
			dcql_query: {
				credentials: [
					{
						id: 'login',
						format: 'dc+sd-jwt',
						meta: { vct_values: ['http://issuer.demo/openid4vci/member'] },
						claims: [
							{ path: ['given_name'] },
							{ path: ['family_name'] },
							{ path: ['email'] },
							{ path: ['name'] },
						],
					},
				],
			},
			policies: {
				vc_policies: [
					'signature',
					'expiration',
					'not-before',
					{ policy: 'allowed-issuer', allowed_issuer: [did] },
				],
			},
		},
	}, null, 2)}\n`;
}

function init() {
	mkdirSync(runtime, { recursive: true, mode: 0o755 });
	chmodSync(runtime, 0o755);
	const ready = join(runtime, 'ready');
	try {
		readFileSync(ready);
		process.stdout.write('demo keys already exist\n');
		return;
	} catch {
		// First start.
	}

	const issuer = generateEcKey('P-256');
	const tokenKey = generateEcKey('P-256');
	const walletAuth = generateEcKey('P-256');
	const nodeKey = generateEcKey('secp256k1');
	const signerKey = generateEcKey('secp256k1');
	const ownerKey = generateEcKey('secp256k1');
	const did = didJwkP256(issuer.x, issuer.y);
	const signer = ethereumAddress(signerKey.x, signerKey.y);
	const owner = ethereumAddress(ownerKey.x, ownerKey.y);
	const nodeAddress = ethereumAddress(nodeKey.x, nodeKey.y);
	if (signer === owner) {
		throw new Error('the registry owner must not be the bridge signing key');
	}
	const keyPassword = secret();
	const ownerPassword = secret();
	const postgresPassword = secret();
	const fireflyDbPassword = secret();
	const walletDbPassword = secret();
	const mariadbRoot = secret();
	const wordpressDb = secret();
	const bridgeToken = secret();
	const webhookSecret = secret();
	const subjectKey = secret();
	const adminPassword = secret();

	const keystore = keystoreV3(signerKey, keyPassword);
	const opened = openKeystore(keystore, keyPassword);
	if (opened.toString('hex') !== scalarHex(signerKey.d)) {
		throw new Error('generated keystore did not open to the signing key');
	}
	const ownerStore = keystoreV3(ownerKey, ownerPassword);
	const openedOwner = openKeystore(ownerStore, ownerPassword);
	if (openedOwner.toString('hex') !== scalarHex(ownerKey.d)) {
		throw new Error('generated keystore did not open to the registry owner key');
	}
	const chain = genesis(nodeAddress, [signer, owner]);
	if (!chain.extraData.includes(nodeAddress.slice(2))) {
		throw new Error('genesis extraData does not name the node key');
	}
	const keyFile = `${keystore.address}`;
	const ownerFile = `${ownerStore.address}`;
	writeAt(signerRoot, `keystore/${keyFile}`, `${JSON.stringify(keystore)}\n`);
	writeAt(signerRoot, `keystore/${keyFile}.toml`, `[metadata]
createdAt = 2019-11-05T08:15:30-05:00
description = "Demo signing key generated at first start"

[signing]
type = "file-based-signer"
key-file = "/data/keystore/${keyFile}"
password-file = "/data/password"
`);
	writeAt(signerRoot, 'password', keyPassword);
	// The owner keystore stays out of the signer directory. setup.sh copies
	// it in for setIssuer and deletes it again, so the running signer cannot
	// sign a trust-list change for the bridge.
	writeAt(ownerRoot, `keystore/${ownerFile}`, `${JSON.stringify(ownerStore)}\n`);
	writeAt(ownerRoot, `keystore/${ownerFile}.toml`, `[metadata]
createdAt = 2019-11-05T08:15:30-05:00
description = "Registry owner. Present in the signer only while setup.sh calls setIssuer."

[signing]
type = "file-based-signer"
key-file = "/data/keystore/${ownerFile}"
password-file = "/data/registry-owner.password"
`);
	writeAt(ownerRoot, 'password', ownerPassword);
	write('nodekey', `${scalarHex(nodeKey.d)}\n`);
	write('genesis.json', `${JSON.stringify(chain, null, 2)}\n`);
	write('ffsigner.yaml', signerConfig());
	write('evmconnect.yaml', evmconnectConfig());
	write('firefly.core.yaml', fireflyConfig(fireflyDbPassword, signer));
	write('signer.address', `${signer}\n`);
	write('registry-owner.address', `${owner}\n`);
	write('issuer.did', `${did}\n`);
	write('issuer-key.conf', `issuerKey = ${hoconJwk(issuer)}
issuerDid = "${did}"
`);
	write('issuer-service.conf', `baseUrl = "http://issuer.demo"
enforcePushedAuthorizationRequests = false
ciTokenKey = """${jsonJwk(tokenKey)}"""
`);
	write('wallet-auth.conf', `signingKey = ${jsonJwk(walletAuth)}
tokenExpiry = "PT24H"
`);
	write('wallet-db.conf', `wallet2-persistence {
  jdbcUrl = "jdbc:postgresql://postgres:5432/wallet"
  driverClassName = "org.postgresql.Driver"
  username = "wallet"
  password = "${walletDbPassword}"
  maximumPoolSize = 5
  minimumIdle = 1
}
`);
	write('bridge.token', `${bridgeToken}\n`);
	write('bridge.queries.json', bridgeQueries(did));
	write('webhook.secret', `${webhookSecret}\n`);
	write('subject.key', `${subjectKey}\n`);
	write('wp-admin.password', `${adminPassword}\n`);
	write('postgres.env', `POSTGRES_USER=postgres
POSTGRES_PASSWORD=${postgresPassword}
POSTGRES_DB=postgres
FIREFLY_DB_PASSWORD=${fireflyDbPassword}
WALLET_DB_PASSWORD=${walletDbPassword}
`);
	write('wordpress.env', `MARIADB_ROOT_PASSWORD=${mariadbRoot}
MARIADB_DATABASE=wordpress
MARIADB_USER=wordpress
MARIADB_PASSWORD=${wordpressDb}
WORDPRESS_DB_HOST=mariadb
WORDPRESS_DB_USER=wordpress
WORDPRESS_DB_PASSWORD=${wordpressDb}
WORDPRESS_DB_NAME=wordpress
`);
	write('ready', 'ok\n');
	process.stdout.write(`demo keys generated for ${signer}, registry owner ${owner}\n`);
}

if (process.argv.includes('--self-test')) {
	selfTest();
	process.stdout.write('ok\n');
} else {
	init();
}
