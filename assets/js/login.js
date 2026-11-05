/**
 * blocLabs SSI Login: drives the credential block on wp-login.php.
 *
 * initiate → show QR / wallet link → poll status → complete → redirect.
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
		qr: $( '[data-ssi-qr]' ),
		open: $( '[data-ssi-open]' ),
		status: $( '[data-ssi-status]' ),
		cancel: $( '[data-ssi-cancel]' ),
	};

	// The server's list (bloclabs_ssi_wallet_url_schemes), as URL.protocol values.
	const WALLET_SCHEMES = ( cfg.schemes || [ 'openid4vp', 'https' ] ).map( ( s ) => String( s ).toLowerCase() + ':' );
	const COMPLETE_RETRIES = 5;
	let run = 0; // Bumped on cancel/restart so stale pollers stop.

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

	function reset() {
		if ( ui.cancel.disabled ) {
			return; // Completing: the session may already exist.
		}
		run++;
		ui.panel.hidden = true;
		ui.start.hidden = false;
		ui.qr.replaceChildren();
	}

	function poll( id, me, delay ) {
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
					poll( id, me, Math.min( 5000, Math.max( 1000, ( r.data.poll_after || 2 ) * 1000 ) ) );
				} else if ( status === 'verified' ) {
					say( 'verified' );
					complete( id, me );
				} else {
					say( status === 'expired' ? 'expired' : status === 'failed' ? 'failed' : 'error' );
					ui.start.hidden = false;
				}
			} ).catch( () => me === run && poll( id, me, 4000 ) );
		}, delay );
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
			renderQr( url );
			ui.open.href = url;
			ui.open.hidden = false;
			say( 'waiting' );
			poll( r.data.attempt, me, ( r.data.poll_after || 2 ) * 1000 );
		} ).catch( () => {
			say( 'error' );
			ui.start.hidden = false;
		} );
	}

	ui.start.addEventListener( 'click', start );
	ui.cancel.addEventListener( 'click', reset );
}() );
