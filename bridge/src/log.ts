/**
 * JSON-lines logger.
 *
 * The bridge is the only component that sees credentials, so the rule for
 * every call site is: log identifiers and outcomes, never claims, subject
 * identifiers, presentations, nonces or tokens. test/logging.test.ts checks
 * a whole login against that rule.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export type LogFields = Record<string, string | number | boolean | null | undefined>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export function isLogLevel(value: string): value is LogLevel {
  return value in LEVELS;
}

export function createLogger(
  level: LogLevel,
  sink: (line: string) => void = (line) => process.stdout.write(line + '\n'),
  now: () => Date = () => new Date(),
): Logger {
  const threshold = LEVELS[level];
  const emit = (entryLevel: LogLevel, message: string, fields?: LogFields): void => {
    if (LEVELS[entryLevel] < threshold) {
      return;
    }
    sink(JSON.stringify({ time: now().toISOString(), level: entryLevel, msg: message, ...fields }));
  };
  return {
    debug: (message, fields) => emit('debug', message, fields),
    info: (message, fields) => emit('info', message, fields),
    warn: (message, fields) => emit('warn', message, fields),
    error: (message, fields) => emit('error', message, fields),
  };
}
