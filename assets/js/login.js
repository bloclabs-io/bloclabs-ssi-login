/**
 * blocLabs SSI Login: drives the credential block on wp-login.php.
 *
 * initiate → ask the wallet (through the browser's Digital Credentials API
 * where it exists and the bridge offered a request, else a QR code and a
 * wallet link) → poll status → complete → redirect.
 * A wallet opened through the link on this device sends the holder back to
 * this page with the attempt in the address (ReturnUrl in PHP); the page
 * then picks the attempt up at the polling step.
 * No framework, no build step. Server data is only ever set with
 * textContent or as a validated href, never as HTML.
 */
( function () {
	'use strict';

	const cfg = window.bloclabsSsi;
	const root = document.getElementById( 'bloclabs-ssi' );
	if ( ! cfg || ! root || ! window.fetch ) {
		return;
	}

	const $ = ( sel ) => root.querySelector( sel );
	const ui = {
		start: $( '[data-ssi-start]' ),
		panel: $( '[data-ssi-panel]' ),
		hint: $( '[data-ssi-hint]' ),
		qr: $( '[data-ssi-qr]' ),
		open: $( '[data-ssi-open]' ),
		status: $( '[data-ssi-status]' ),
		cancel: $( '[data-ssi-cancel]' ),
	};

	// The server's list (bloclabs_ssi_wallet_url_schemes), as URL.protocol values.
	const WALLET_SCHEMES = ( cfg.schemes || [ 'openid4vp', 'https' ] ).map( ( s ) => String( s ).toLowerCase() + ':' );
	const COMPLETE_RETRIES = 5;
	const MAX_DC_API_REQUESTS = 8;
	let run = 0; // Bumped on cancel/restart so stale pollers stop.
	let browserPrompt = null; // AbortController of the open Digital Credentials API prompt, if any.

	root.hidden = false;

	function say( key ) {
		ui.status.textContent = cfg.i18n[ key ] || '';
	}

	function api( path, options ) {
		const headers = Object.assign( { Accept: 'application/json' }, options && options.body ? { 'Content-Type': 'application/json' } : {} );
		headers[ cfg.tokenHeader ] = cfg.token;
		return fetch( cfg.restBase + path, Object.assign( { credentials: 'same-origin', cache: 'no-store', headers }, options ) )
			.then( ( res ) => res.json().catch( () => ( {} ) ).then( ( data ) => ( { ok: res.ok, status: res.status, data } ) ) );
	}

	function safeWalletUrl( url ) {
		try {
			const parsed = new URL( url );
			return WALLET_SCHEMES.includes( parsed.protocol ) ? parsed.href : null;
		} catch ( e ) {
			return null;
		}
	}

	/**
	 * The bridge's `dc_api` object (docs/BRIDGE-API.md), checked before use: the
	 * requests for navigator.credentials.get() and the HTTPS route the wallet's
	 * answer is posted to (plain http only when this page is plain http itself,
	 * a localhost test stack). Null when this browser cannot use it.
	 */
	function browserOffer( offer ) {
		if ( ! offer || typeof offer !== 'object' || ! Array.isArray( offer.requests ) || typeof offer.response_url !== 'string' ) {
			return null;
		}
		if ( ! window.isSecureContext || typeof window.DigitalCredential !== 'function' ) {
			return null;
		}
		const nav = window.navigator;
		if ( ! nav || ! nav.credentials || typeof nav.credentials.get !== 'function' ) {
			return null;
		}
		let responseUrl;
		try {
			const parsed = new URL( offer.response_url );
			responseUrl = parsed.protocol === 'https:' || ( parsed.protocol === 'http:' && window.location.protocol === 'http:' ) ? parsed.href : null;
		} catch ( e ) {
			responseUrl = null;
		}
		if ( ! responseUrl ) {
			return null;
		}
		const allows = typeof window.DigitalCredential.userAgentAllowsProtocol === 'function'
			? ( protocol ) => {
				try {
					return window.DigitalCredential.userAgentAllowsProtocol( protocol );
				} catch ( e ) {
					return true; // Let the call itself decide.
				}
			}
			: () => true;
		const requests = offer.requests
			.filter( ( q ) => q && typeof q === 'object' && typeof q.protocol === 'string' && q.protocol !== '' && q.data && typeof q.data === 'object' )
			.filter( ( q ) => allows( q.protocol ) )
			.slice( 0, MAX_DC_API_REQUESTS )
			.map( ( q ) => ( { protocol: q.protocol, data: q.data } ) );
		return requests.length ? { requests, responseUrl } : null;
	}

	/** What the wallet answered, as the verifier's response route takes it: {protocol, data}. */
	function credentialAnswer( credential ) {
		if ( ! credential || typeof credential !== 'object' || typeof credential.protocol !== 'string' ) {
			return null;
		}
		let data = credential.data;
		if ( typeof data === 'string' ) { // Earlier Chrome versions hand the response over as JSON text.
			try {
				data = JSON.parse( data );
			} catch ( e ) {
				return null;
			}
		}
		return data && typeof data === 'object' ? { protocol: credential.protocol, data } : null;
	}

	/**
	 * Asks the wallet through the browser and posts its answer to the verifier.
	 * Resolves true once the verifier accepted the answer (the poller then sees the
	 * decision), false when the holder dismissed the prompt, no wallet answered, or
	 * the answer could not be delivered: the QR code and wallet link take over.
	 * The browser binds the request to this page's origin, so no cookie goes along.
	 */
	function askBrowser( offer, me ) {
		const prompt = new AbortController();
		browserPrompt = prompt;
		const nav = window.navigator;
		return Promise.resolve()
			.then( () => nav.credentials.get( { digital: { requests: offer.requests }, signal: prompt.signal } ) )
			.then( ( credential ) => {
				if ( me !== run ) {
					return false;
				}
				const answer = credentialAnswer( credential );
				if ( ! answer ) {
					return false;
				}
				return fetch( offer.responseUrl, {
					method: 'POST',
					mode: 'cors',
					credentials: 'omit',
					cache: 'no-store',
					redirect: 'error',
					headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
					body: JSON.stringify( answer ),
				} ).then( ( res ) => res.ok, () => false );
			}, () => false )
			.then( ( delivered ) => {
				if ( browserPrompt === prompt ) {
					browserPrompt = null;
				}
				return delivered;
			} );
	}

	function renderQr( text ) {
		ui.qr.replaceChildren();
		if ( typeof window.qrcode !== 'function' ) {
			ui.qr.hidden = true; // No encoder vendored: the wallet link still works.
			return;
		}
		try {
			const qr = window.qrcode( 0, 'M' );
			qr.addData( text );
			qr.make();
			const img = document.createElement( 'img' );
			img.src = qr.createDataURL( 6, 2 );
			img.alt = '';
			ui.qr.appendChild( img );
			ui.qr.hidden = false;
		} catch ( e ) {
			ui.qr.hidden = true; // Oversize requests still have a wallet link and a poller.
		}

	}

	/** The cross-device path: a QR code to scan and a link for a wallet app on this device. */
	function showWalletLink( url ) {
		renderQr( url );
		ui.open.href = url;
		ui.open.hidden = false;
		if ( ui.hint ) {
			ui.hint.hidden = false;
		}
		say( 'waiting' );
	}

	function reset() {
		if ( ui.cancel.disabled ) {
			return; // Completing: the session may already exist.
		}
		run++;
		if ( browserPrompt ) {
			browserPrompt.abort();
			browserPrompt = null;
		}
		ui.panel.hidden = true;
		ui.start.hidden = false;
		ui.qr.replaceChildren();
	}

	/**
	 * @param {boolean} [resumed] The attempt came back with the holder from the wallet (resume): an
	 *                            attempt this browser does not hold is then reported as such.
	 */
	function poll( id, me, delay, resumed ) {
		window.setTimeout( () => {
			if ( me !== run ) {
				return;
			}
			api( 'status/' + encodeURIComponent( id ), { method: 'GET' } ).then( ( r ) => {
				if ( me !== run ) {
					return;
				}
				if ( r.status === 404 ) {
					ui.qr.replaceChildren();
					ui.qr.hidden = true;
					ui.open.removeAttribute( 'href' );
					ui.open.hidden = true;
				}
				const status = r.ok ? r.data.status : 'error';
				if ( status === 'pending' ) {
					poll( id, me, Math.min( 5000, Math.max( 1000, ( r.data.poll_after || 2 ) * 1000 ) ), resumed );
				} else if ( status === 'verified' ) {
					say( 'verified' );
					complete( id, me );
				} else {
					say( status === 'expired' ? 'expired' : status === 'failed' ? 'failed' : resumed && r.status === 404 ? 'unknown' : 'error' );
					ui.start.hidden = false;
				}
			} ).catch( () => me === run && poll( id, me, 4000, resumed ) );
		}, delay );
	}

	/**
	 * The attempt a wallet on this device sent the holder back here to finish, as
	 * ReturnUrl in PHP put it in the address, or null. The parameter is dropped from
	 * the address at once, with the verifier's response code next to it, so that a
	 * reload, the back button or a shared link does not replay it. The id alone
	 * opens nothing: the status and complete routes still need this browser's
	 * binding cookie, which the fetches carry as always.
	 */
	function resumeId() {
		const history = window.history;
		if ( ! cfg.resumeParam || ! window.location || ! history || typeof history.replaceState !== 'function' ) {
			return null;
		}
		let url;
		try {
			url = new URL( window.location.href );
		} catch ( e ) {
			return null;
		}
		const id = url.searchParams.get( cfg.resumeParam );
		if ( id === null ) {
			return null;
		}
		url.searchParams.delete( cfg.resumeParam );
		url.searchParams.delete( 'response_code' );
		try {
			history.replaceState( history.state, '', url.href );
		} catch ( e ) {
			// A history the page may not write: the address keeps the parameter, and the attempt its single use.
		}
		return /^[a-f0-9]{32}$/.test( id ) ? id : null;
	}

	/** Finishes an attempt this browser started and a wallet on this device answered: no new request, the outcome only. */
	function resume( id ) {
		const me = ++run;
		ui.cancel.disabled = false;
		ui.start.hidden = true;
		ui.panel.hidden = false;
		ui.qr.replaceChildren();
		ui.qr.hidden = true;
		ui.open.removeAttribute( 'href' );
		ui.open.hidden = true;
		if ( ui.hint ) {
			ui.hint.hidden = true;
		}
		say( 'resuming' );
		poll( id, me, 0, true );
	}

	function complete( id, me, tries ) {
		ui.cancel.disabled = true;
		api( 'complete', { method: 'POST', body: JSON.stringify( { attempt: id } ) } ).then( ( r ) => {
			if ( r.ok && r.data.redirect_to ) {
				window.location.assign( r.data.redirect_to ); // Logged in: leave, whatever else happened on the page.
				return;
			}
			// The verifier attested a moment before serving its result: try again shortly.
			if ( r.data && r.data.code === 'bloclabs_ssi_retry' && ( tries || 0 ) < COMPLETE_RETRIES ) {
				window.setTimeout( () => complete( id, me, ( tries || 0 ) + 1 ), 1500 );
				return;
			}
			ui.cancel.disabled = false;
			ui.status.textContent = ( r.data && r.data.message ) || cfg.i18n.error;
			ui.start.hidden = false;
		} ).catch( () => {
			// A dropped response: the attempt may still be valid, so retry like a 'not ready yet'.
			if ( ( tries || 0 ) < COMPLETE_RETRIES ) {
				window.setTimeout( () => complete( id, me, ( tries || 0 ) + 1 ), 1500 );
				return;
			}
			ui.cancel.disabled = false;
			say( 'error' );
			ui.start.hidden = false;
		} );
	}

	function start() {
		const me = ++run;
		ui.cancel.disabled = false;
		ui.start.hidden = true;
		ui.panel.hidden = false;
		ui.qr.replaceChildren();
		ui.qr.hidden = true;
		ui.open.removeAttribute( 'href' );
		ui.open.hidden = true;
		if ( ui.hint ) {
			ui.hint.hidden = true;
		}
		say( 'starting' );

		api( 'initiate', { method: 'POST', body: JSON.stringify( { redirect_to: cfg.redirectTo } ) } ).then( ( r ) => {
			if ( me !== run ) {
				return;
			}
			const url = r.ok ? safeWalletUrl( r.data.wallet_url ) : null;
			if ( ! url ) {
				ui.status.textContent = ( r.data && r.data.message ) || cfg.i18n.error;
				ui.start.hidden = false;
				return;
			}
			// Whichever way the wallet answers, the decision arrives through the status route.
			poll( r.data.attempt, me, ( r.data.poll_after || 2 ) * 1000 );
			const offer = browserOffer( r.data.dc_api );
			if ( ! offer ) {
				showWalletLink( url );
				return;
			}
			// Same-device login: the browser asks the wallet, bound to this page's origin.
			// This runs on the click's user activation, which the API requires.
			say( 'waiting' );
			askBrowser( offer, me ).then( ( delivered ) => {
				if ( me === run && ! delivered ) {
					showWalletLink( url );
				}
			} );
		} ).catch( () => {
			say( 'error' );
			ui.start.hidden = false;
		} );
	}

	ui.start.addEventListener( 'click', start );
	ui.cancel.addEventListener( 'click', reset );

	const returned = resumeId();
	if ( returned ) {
		resume( returned );
	}
}() );
