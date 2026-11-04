<?php
/**
 * Verifier double installed through `bloclabs_ssi_verifier_client`.
 *
 * Results default to the subject and presentation hash of the captured FireFly event.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration\Support;

use BlocLabs\SsiLogin\Verifier\PresentationOffer;
use BlocLabs\SsiLogin\Verifier\PresentationRequest;
use BlocLabs\SsiLogin\Verifier\PresentationResult;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class VerifierFake implements VerifierClient {

	private static ?self $instance = null;

	public ?VerifierException $create_error = null;

	public ?VerifierException $result_error = null;

	public ?string $subject_id = null;

	public ?string $issuer = null;

	public ?string $presentation_hash = null;

	public int $creates = 0;

	public int $fetches = 0;

	public ?PresentationRequest $last_request = null;

	public ?string $verifier_ref = null;

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function reset(): void {
		$this->create_error      = null;
		$this->result_error      = null;
		$this->subject_id        = null;
		$this->issuer            = null;
		$this->presentation_hash = null;
		$this->creates           = 0;
		$this->fetches           = 0;
		$this->last_request      = null;
		$this->verifier_ref      = null;
	}

	public function create_request( PresentationRequest $request ): PresentationOffer {
		++$this->creates;
		$this->last_request = $request;
		if ( null !== $this->create_error ) {
			throw $this->create_error;
		}

		return new PresentationOffer(
			$this->verifier_ref ?? 'vr_integration',
			'openid4vp://?client_id=x509_san_dns:verifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest'
		);
	}

	public function fetch_result( string $verifier_ref ): PresentationResult {
		if ( '' === $verifier_ref ) {
			throw new VerifierException( 'Missing verifier reference.' );
		}
		++$this->fetches;
		if ( null !== $this->result_error ) {
			throw $this->result_error;
		}

		$fixture = CapturedLoginEvent::fixture();

		return new PresentationResult(
			$this->subject_id ?? (string) $fixture['subject'],
			$this->issuer ?? 'did:web:issuer.example',
			strtolower( (string) ( $this->presentation_hash ?? $fixture['presentation_hash'] ) ),
			array( 'name' => 'Ada' )
		);
	}
}
