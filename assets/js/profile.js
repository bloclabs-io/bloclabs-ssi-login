/**
 * Self-service credential linking; WordPress session and browser binding are both required.
 * A wallet opened through the link on this device sends the holder back here with the
 * attempt in the address (ReturnUrl in PHP); the page then finishes that attempt.
 */
( function () {
	'use strict';
	const cfg = window.bloclabsSsiProfile;
	const root = document.getElementById( 'bloclabs-ssi-profile' );
	if ( ! cfg || ! root || ! window.fetch ) {
		return;
	}
	const $ = ( selector ) => root.querySelector( selector );
	const start = $( '[data-ssi-start]' );
	const panel = $( '[data-ssi-panel]' );
	const qr = $( '[data-ssi-qr]' );
	const open = $( '[data-ssi-open]' );
	const cancel = $( '[data-ssi-cancel]' );
	const status = $( '[data-ssi-status]' );
	let run = 0;
	root.hidden = false;

	async function api( path, body ) {
		const headers = { 'X-WP-Nonce': cfg.nonce, Accept: 'application/json', 'Content-Type': 'application/json' };
		headers[ cfg.tokenHeader ] = cfg.token;
		const response = await fetch( cfg.restBase + path, {
			method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers,
			...( body ? { body: JSON.stringify( body ) } : {} ),
		} );
		const data = await response.json();
		if ( ! response.ok ) {
			const error = new Error( data.message || cfg.i18n.error );
			error.code = data.code;
			throw error;
		}
		return data;
	}
	function clearOffer() {
		qr.replaceChildren();
		open.removeAttribute( 'href' );
		open.hidden = true;
	}
	function stop() {
		run++;
		clearOffer();
		panel.hidden = true;
		start.disabled = false;
		cancel.disabled = false;
	}
	function fail( error ) {
		stop();
		status.textContent = error.message || cfg.i18n.error;
	}
	async function complete( id, me, tries = 0 ) {
		cancel.disabled = true;
		clearOffer();
		try {
			await api( 'complete', { attempt: id } );
			window.location.reload();
		} catch ( error ) {
			if ( me === run && error.code === 'bloclabs_ssi_retry' && tries < 5 ) {
				window.setTimeout( () => complete( id, me, tries + 1 ), 1500 );
			} else if ( me === run ) {
				fail( error );
			}
		}
	}
	/**
	 * @param {boolean} [resumed] The attempt came back with the holder from the wallet (resume): an
	 *                            attempt this browser does not hold is then reported as such.
	 */
	function poll( id, me, resumed, delay = 2000 ) {
		window.setTimeout( async () => {
			if ( me !== run ) {
				return;
			}
			try {
				const data = await api( 'status/' + encodeURIComponent( id ) );
				if ( me !== run ) {
					return;
				}
				if ( data.status === 'pending' ) {
					poll( id, me, resumed );
				} else if ( data.status === 'verified' ) {
					complete( id, me );
				} else if ( data.status === 'consumed' ) {
					window.location.reload(); // Linked meanwhile from another tab of this browser: show it.
				} else {
					fail( new Error( cfg.i18n.error ) );
				}
			} catch ( error ) {
				if ( me === run ) {
					fail( resumed && error.code === 'bloclabs_ssi_unknown' ? new Error( cfg.i18n.unknown ) : error );
				}
			}
		}, delay );
	}
	/**
	 * The attempt a wallet on this device sent the holder back here to finish, as ReturnUrl in PHP
	 * put it in the address, or null. The parameter is dropped from the address at once, with the
	 * verifier's response code next to it, so that a reload or the back button does not replay it.
	 * The id alone opens nothing: the status and complete routes still need this browser's binding
	 * cookie and this account's session, which the fetches carry as always.
	 */
	function resumeId() {
		const history = window.history;
		if ( ! cfg.resumeParam || ! window.location || ! history || typeof history.replaceState !== 'function' ) {
			return null;
		}
		let url;
		try {
			url = new URL( window.location.href );
		} catch ( error ) {
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
		} catch ( error ) { /* A history the page may not write: the address keeps the parameter, and the attempt its single use. */ }
		return /^[a-f0-9]{32}$/.test( id ) ? id : null;
	}
	/** Finishes an attempt this browser started and a wallet on this device answered: no new request, the outcome only. */
	function resume( id ) {
		stop();
		const me = run;
		start.disabled = true;
		panel.hidden = false;
		status.textContent = cfg.i18n.resuming;
		poll( id, me, true, 0 );
	}
	start.addEventListener( 'click', async () => {
		stop();
		const me = run;
		start.disabled = true;
		panel.hidden = false;
		status.textContent = cfg.i18n.waiting;
		try {
			const data = await api( 'initiate', { purpose: 'link' } );
			if ( me !== run ) {
				return;
			}
			const url = new URL( data.wallet_url );
			if ( ! cfg.schemes.map( ( scheme ) => scheme.toLowerCase() + ':' ).includes( url.protocol ) ) {
				throw new Error( cfg.i18n.error );
			}
			open.href = url.href;
			open.hidden = false;
			if ( typeof window.qrcode === 'function' ) {
				try {
					const code = window.qrcode( 0, 'M' );
					code.addData( url.href );
					code.make();
					const img = document.createElement( 'img' );
					img.src = code.createDataURL( 6, 2 );
					img.alt = '';
					qr.appendChild( img );
				} catch ( error ) { /* The same-device link remains available. */ }
			}
			poll( data.attempt, me );
		} catch ( error ) {
			if ( me === run ) {
				fail( error );
			}
		}
	} );
	cancel.addEventListener( 'click', () => {
		if ( ! cancel.disabled ) {
			stop();
			status.textContent = '';
		}
	} );
	const returned = resumeId();
	if ( returned ) {
		resume( returned );
	}
	root.querySelectorAll( '[data-ssi-unlink]' ).forEach( ( button ) => {
		button.addEventListener( 'click', async () => {
			if ( ! window.confirm( cfg.i18n.confirm ) ) {
				return;
			}
			button.disabled = true;
			try {
				await api( 'profile/unlink', { identity: Number( button.dataset.ssiUnlink ) } );
				window.location.reload();
			} catch ( error ) {
				status.textContent = error.message || cfg.i18n.error;
				button.disabled = false;
			}
		} );
	} );
}() );
