/** Convert an operator's PEM key and leaf-first certificate chain to walt.id 1.2.0 config. */
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

try {
  const { values } = parseArgs({ options: {
    key: { type: 'string' }, cert: { type: 'string' }, url: { type: 'string' },
    output: { type: 'string' }, mode: { type: 'string', default: 'x509_san_dns' },
    name: { type: 'string', default: 'Credential login' },
  } });
  for (const name of ['key', 'cert', 'url', 'output']) {
    if (!values[name]) throw new Error(`--${name} is required`);
  }
  if (!['x509_san_dns', 'x509_hash'].includes(values.mode)) throw new Error('Invalid --mode');
  const url = new URL(values.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.pathname !== '/') throw new Error('--url must be an HTTPS origin');
  const key = createPrivateKey(readFileSync(values.key));
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('Use an EC P-256 signing key');
  const pem = readFileSync(values.cert, 'utf8');
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks?.length) throw new Error('No PEM certificates found');
  const chain = blocks.map((block) => new X509Certificate(block));
  const leaf = chain[0];
  if (!leaf.checkPrivateKey(key)) throw new Error('Leaf certificate does not match the private key');
  if (chain.some((cert) => Date.now() < Date.parse(cert.validFrom) || Date.now() >= Date.parse(cert.validTo))) {
    throw new Error('Certificate is expired or not yet valid');
  }
  // OpenID4VP DNS identifiers require a dNSName SAN, never a CN fallback or wildcard.
  if (values.mode === 'x509_san_dns' && !leaf.checkHost(url.hostname, { subject: 'never', wildcards: false })) {
    throw new Error('Leaf certificate needs a DNS SAN matching the HTTPS host');
  }
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i].checkIssued(chain[i + 1]) || !chain[i].verify(chain[i + 1].publicKey)) {
      throw new Error('Certificates must form a leaf-first chain');
    }
  }
  const identifier = values.mode === 'x509_san_dns' ? url.hostname
    : createHash('sha256').update(leaf.raw).digest('base64url');
  const config = {
    clientMetadata: { client_name: values.name },
    urlPrefix: `${url.origin}/verification-session`, urlHost: 'openid4vp://authorize',
    clientId: `${values.mode}:${identifier}`, key: { type: 'jwk', jwk },
    x5c: chain.map((cert) => cert.raw.toString('base64')),
  };
  // Contains private material: never print it, replace an existing file, or create it world-readable.
  writeFileSync(values.output, JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log('Created signing configuration; keep this file private.');
} catch (error) {
  // Crypto parser errors may include input details; keep diagnostics limited to our own validation messages.
  const safe = /^(--|Invalid --mode|Use an EC|No PEM|Leaf certificate|Certificate is|Certificates must)/;
  console.error(safe.test(error.message) ? error.message : 'Could not create signing configuration (check PEM inputs and output path).');
  process.exitCode = 1;
}
