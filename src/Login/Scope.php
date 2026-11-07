<?php
/**
 * What an agent token may do: scope names and the capability sets behind them.
 *
 * ADR 0007 §4. A token's scope is the intersection of what the agent asked
 * for, what its credential allows and what the site allows; it can only
 * narrow. No scope may carry a capability from the denylist, whatever a
 * site's `bloclabs_ssi_agent_scopes` filter says: the filter's result is
 * checked against it. Enforcement per request is the bearer filter's (4/7).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\Config\Settings;

final class Scope {

	public const READ    = 'read';
	public const CONTENT = 'content';

	/** Filter adding a site's own scopes: `name => [capabilities]`. */
	public const FILTER = 'bloclabs_ssi_agent_scopes';

	/**
	 * Capabilities no scope may ever contain: what UserResolver::safe_role()
	 * refuses a self-registered account, and everything that administers users,
	 * code or the network. Any `manage_network*` capability is denied too.
	 */
	public const DENIED = array(
		'manage_options',
		'edit_users',
		'promote_users',
		'create_users',
		'delete_users',
		'unfiltered_html',
		'unfiltered_upload',
		'install_plugins',
		'activate_plugins',
		'edit_plugins',
		'edit_themes',
		'install_themes',
		'update_core',
	);

	private const DENIED_PREFIX = 'manage_network';

	/** A scope name: lowercase, starts with a letter, at most 32 characters. */
	private const NAME = '/^[a-z][a-z0-9_-]{0,31}$/';

	/**
	 * The two scopes 0.4 defines.
	 *
	 * @return array<string, list<string>>
	 */
	public static function built_in(): array {
		return array(
			self::READ    => array( 'read' ),
			self::CONTENT => array( 'read', 'edit_posts', 'edit_published_posts', 'publish_posts', 'delete_posts', 'upload_files' ),
		);
	}

	/**
	 * Every scope the plugin knows, built-in and from the site's filter, with
	 * the denylist applied to the result.
	 *
	 * @return array<string, list<string>>
	 */
	public static function catalogue(): array {
		/**
		 * Add a site's own scopes, or change the built-in ones. A scope is a name
		 * (`[a-z][a-z0-9_-]*`) and a list of capability names; a denied capability
		 * is dropped from any scope, and a malformed entry is ignored.
		 *
		 * @param array<string, list<string>> $scopes
		 */
		return self::normalise( apply_filters( 'bloclabs_ssi_agent_scopes', self::built_in() ) );
	}

	/**
	 * Well-formed scopes only, with denied capabilities removed.
	 *
	 * @param mixed $scopes What the filter returned.
	 * @return array<string, list<string>>
	 */
	public static function normalise( $scopes ): array {
		if ( ! is_array( $scopes ) ) {
			return array();
		}
		$out = array();
		foreach ( $scopes as $name => $capabilities ) {
			if ( ! is_string( $name ) || 1 !== preg_match( self::NAME, $name ) || ! is_array( $capabilities ) ) {
				continue;
			}
			$kept = array();
			foreach ( $capabilities as $capability ) {
				if ( is_string( $capability ) && '' !== $capability && ! self::is_denied( $capability ) ) {
					$kept[ $capability ] = true;
				}
			}
			$out[ $name ] = array_keys( $kept );
		}
		return $out;
	}

	public static function is_denied( string $capability ): bool {
		$capability = strtolower( $capability );
		return in_array( $capability, self::DENIED, true ) || str_starts_with( $capability, self::DENIED_PREFIX );
	}

	/**
	 * Scope names out of a request body, a credential claim or a setting:
	 * a list of strings, or one string of names separated by spaces or commas.
	 * Unknown names are kept; intersecting with the site's scopes drops them.
	 *
	 * @param mixed $value
	 * @return list<string> Well-formed names, in order, without duplicates.
	 */
	public static function names( $value ): array {
		if ( is_string( $value ) ) {
			$value = preg_split( '/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( ! is_array( $value ) ) {
			return array();
		}
		$names = array();
		foreach ( $value as $name ) {
			if ( is_string( $name ) && 1 === preg_match( self::NAME, $name ) ) {
				$names[ $name ] = true;
			}
		}
		return array_keys( $names );
	}

	/**
	 * The scopes the site allows at all (`agent_scopes`), among those it knows.
	 *
	 * @return list<string>
	 */
	public static function site( Settings $settings ): array {
		return array_values( array_intersect( self::names( $settings->get( 'agent_scopes' ) ), array_keys( self::catalogue() ) ) );
	}

	/**
	 * What a token gets: requested ∩ credential ∩ site, in the order requested.
	 * Empty means refuse.
	 *
	 * @param list<string>      $requested  What the agent asked for.
	 * @param list<string>|null $credential The credential's `scope` claim; null when it names none (no limit).
	 * @param list<string>      $site       The site's scopes.
	 * @return list<string>
	 */
	public static function grant( array $requested, ?array $credential, array $site ): array {
		$granted = array_intersect( $requested, $site );
		if ( null !== $credential ) {
			$granted = array_intersect( $granted, $credential );
		}
		return array_values( $granted );
	}

	/**
	 * The capabilities behind a token's scope names, for enforcement.
	 *
	 * @param list<string> $names
	 * @return list<string>
	 */
	public static function capabilities( array $names ): array {
		$catalogue = self::catalogue();
		$out       = array();
		foreach ( $names as $name ) {
			foreach ( $catalogue[ $name ] ?? array() as $capability ) {
				$out[ $capability ] = true;
			}
		}
		return array_keys( $out );
	}
}
