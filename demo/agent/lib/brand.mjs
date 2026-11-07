/**
 * The blocLabs look, as far as a terminal has one (AGENTS.md, "blocLabs look
 * and feel"): the wordmark, blocLabs orange #ff782d for headings and the
 * accent, dark grey for body text. Colour only on a terminal, never in a
 * pipe, and never when NO_COLOR is set.
 */

const ORANGE = '\u001b[38;2;255;120;45m';
const DARK = '\u001b[38;2;51;51;51m';
const BOLD = '\u001b[1m';
const DIM = '\u001b[2m';
const RESET = '\u001b[0m';

export function colours(stream = process.stdout, env = process.env) {
	return Boolean(stream.isTTY) && !('NO_COLOR' in env) && env.TERM !== 'dumb';
}

export function paint(on) {
	const wrap = (code) => (text) => (on ? `${code}${text}${RESET}` : text);
	return {
		accent: wrap(ORANGE),
		heading: wrap(`${BOLD}${ORANGE}`),
		body: wrap(DARK),
		dim: wrap(DIM),
		bold: wrap(BOLD),
	};
}

/** The wordmark line every command prints first. */
export function banner(p) {
	return `${p.heading('bloc')}${p.bold('Labs')} ${p.dim('·')} ${p.body('SSI Login agent')}`;
}

/** A step line: an orange bullet, then what happened. */
export function step(p, text) {
	return `${p.accent('●')} ${text}`;
}

export function keyValue(p, key, value) {
	return `  ${p.dim(key.padEnd(12))} ${value}`;
}
