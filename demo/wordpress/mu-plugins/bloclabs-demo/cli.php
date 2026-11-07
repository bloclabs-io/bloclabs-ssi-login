<?php
/**
 * Demo-only WP-CLI commands for the agent walkthrough (demo/agent.sh).
 *
 * `wp bloclabs-demo link-agent` links an agent's own subject id to an account,
 * which is what "Link a credential" on the profile screen does for a person.
 * `wp bloclabs-demo allow-agents` turns on "Agents may act for this account"
 * for the account a subject id is linked to, which that account's owner does
 * on their profile screen. Neither belongs in the plugin: here they stand in
 * for the two people a real site has, so the demo needs no browser at all.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

use BlocLabs\SsiLogin\Identity\AgentDelegation;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Plugin;

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * wp bloclabs-demo <link-agent|allow-agents>
 *
 * phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter -- WP-CLI passes ($args, $assoc_args) to every subcommand.
 */
final class Bloclabs_Ssi_Demo_Command {

	/**
	 * Links an agent's subject id to an account.
	 *
	 * ## OPTIONS
	 *
	 * --subject=<id>
	 * : The agent's subject id (did:jwk:… or a JWK thumbprint URI), as `agent.mjs whoami` prints it.
	 *
	 * [--user=<login>]
	 * : The account to link it to. Default nightly-agent.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bloclabs-demo link-agent --subject=did:jwk:eyJr… --user=nightly-agent
	 *
	 * @param list<string>          $args
	 * @param array<string, string> $assoc
	 */
	public function link_agent( array $args, array $assoc ): void {
		$plugin  = Plugin::instance();
		$subject = $this->subject( $assoc );
		$login   = (string) ( $assoc['user'] ?? 'nightly-agent' );
		$user    = get_user_by( 'login', $login );
		if ( ! $user instanceof WP_User ) {
			\WP_CLI::error( sprintf( 'There is no account %s.', $login ) );
		}

		$key    = $plugin->settings()->subject_key();
		$hash   = hash_hmac( 'sha256', $subject, $key ); // What UserResolver::subject_hash() computes.
		$linked = $plugin->identities()->user_id_for( $hash );
		if ( $linked === (int) $user->ID ) {
			\WP_CLI::success( sprintf( 'That subject id is already linked to %s (user %d).', $login, $user->ID ) );
			return;
		}
		if ( null !== $linked ) {
			\WP_CLI::error( sprintf( 'That subject id is linked to another account (user %d). Unlink it on that profile first.', $linked ) );
		}
		if ( ! $plugin->identities()->link( $hash, (int) $user->ID, IdentityRepository::label( $subject, $key ), null ) ) {
			\WP_CLI::error( 'The link could not be stored.' );
		}
		\WP_CLI::success( sprintf( 'Linked the agent to %s (user %d). A token for it logs in as this account, within its role.', $login, $user->ID ) );
	}

	/**
	 * Lets agents act for the account a subject id is linked to.
	 *
	 * ## OPTIONS
	 *
	 * --subject=<id>
	 * : The principal's subject id: the DID of the wallet key that logged in to the account.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bloclabs-demo allow-agents --subject=did:key:z6Mk…
	 *
	 * @param list<string>          $args
	 * @param array<string, string> $assoc
	 */
	public function allow_agents( array $args, array $assoc ): void {
		$plugin  = Plugin::instance();
		$subject = $this->subject( $assoc );
		$linked  = $plugin->identities()->user_id_for( hash_hmac( 'sha256', $subject, $plugin->settings()->subject_key() ) );
		if ( null === $linked ) {
			\WP_CLI::error( 'No account is linked to that subject id. Log in with that credential once first.' );
		}
		if ( ! class_exists( AgentDelegation::class ) ) {
			\WP_CLI::error( 'This build of the plugin has no agent delegation (ADR 0007 part 2 and later).' );
		}
		AgentDelegation::allow( $linked, true );
		$user = get_userdata( $linked );
		\WP_CLI::success( sprintf( 'Agents may now act for %s (user %d).', $user instanceof WP_User ? $user->user_login : '?', $linked ) );
	}

	/**
	 * @param array<string, string> $assoc
	 */
	private function subject( array $assoc ): string {
		$subject = trim( (string) ( $assoc['subject'] ?? '' ) );
		if ( 1 !== preg_match( '/^(did:[a-z0-9]+:[A-Za-z0-9._:%-]+|urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]+)$/', $subject ) ) {
			\WP_CLI::error( '--subject must be a DID (did:jwk:…, did:key:…) or a JWK thumbprint URI.' );
		}
		return $subject;
	}
}

\WP_CLI::add_command( 'bloclabs-demo', 'Bloclabs_Ssi_Demo_Command' );
