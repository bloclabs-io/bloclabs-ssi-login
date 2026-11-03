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

	const WALLET_SCHEMES = [ 'openid4vp:', 'https:' ]; // Mirror of the bloclabs_ssi_wallet_url_schemes filter default.
	let run = 0; // Bumped on cancel/restart so stale pollers stop.

	root.hidden = false;

	function say( key ) {
		ui.status.textContent = cfg.i18n[ key ] || '';
	}

	function api( path, options ) {
		const headers = Object.assign( { Accept: 'application/json' }, options && options.body ? { 'Content-Type': 'application/json' } : {} );
		headers[ cfg.nonceHeader ] = cfg.nonce;
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
		const qr = window.qrcode( 0, 'M' );
		qr.addData( text );
		qr.make();
		const img = document.createElement( 'img' );
		img.src = qr.createDataURL( 6, 2 );
		img.alt = '';
		ui.qr.appendChild( img );
		ui.qr.hidden = false;
	}

	function reset() {
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

	function complete( id, me ) {
		api( 'complete', { method: 'POST', body: JSON.stringify( { attempt: id } ) } ).then( ( r ) => {
			if ( me !== run ) {
				return;
			}
			if ( r.ok && r.data.redirect_to ) {
				window.location.assign( r.data.redirect_to );
				return;
			}
			ui.status.textContent = ( r.data && r.data.message ) || cfg.i18n.error;
			ui.start.hidden = false;
		} );
	}

	function start() {
		const me = ++run;
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
