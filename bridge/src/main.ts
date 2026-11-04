/**
 * Entry point: configuration from the environment, then listen.
 */

import { Bridge } from './bridge.js';
import { ConfigError, loadConfig } from './config.js';
import { FireFlyClient } from './firefly.js';
import { createLogger } from './log.js';
import { createServer } from './server.js';
import { RequestStore } from './store.js';
import { VerifierClient } from './verifier.js';

const SWEEP_INTERVAL_MS = 15_000;
const SHUTDOWN_TIMEOUT_MS = 30_000;

function main(): void {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) {
      process.stderr.write(`bridge: ${error.message}\n`);
      process.exit(1);
    }
    throw error;
  }

  const log = createLogger(config.logLevel);
  const bridge = new Bridge({
    config,
    store: new RequestStore(),
    verifier: new VerifierClient(config.verifierUrl),
    firefly: new FireFlyClient(config.firefly),
    log,
  });
  const server = createServer(bridge, config, log);
  const sweeper = setInterval(() => bridge.sweep(), SWEEP_INTERVAL_MS);
  sweeper.unref();

  server.listen(config.listenPort, config.listenHost, () => {
    log.info('bridge listening', {
      host: config.listenHost,
      port: config.listenPort,
      verifier: config.verifierUrl,
      firefly: config.firefly.url,
      queries: Object.keys(config.queries).join(','),
    });
  });

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) {
      return;
    }
    stopping = true;
    log.info('shutting down', { signal });
    clearInterval(sweeper);
    server.close();
    const timer = setTimeout(() => process.exit(0), SHUTDOWN_TIMEOUT_MS);
    timer.unref();
    void bridge.idle().then(() => process.exit(0));
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}

main();
