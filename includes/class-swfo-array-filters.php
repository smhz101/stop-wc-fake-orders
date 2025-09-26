<?php
/**
 * Pure helpers for filtering arrays (testable, reuse in AJAX and page).
 */
final class SWFO_Array_Filters {

	public static function events_from_request() {
		return array(
			'q'    => isset( $_GET['events_q'] )    ? sanitize_text_field( wp_unslash( $_GET['events_q'] ) )    : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'type' => isset( $_GET['events_type'] ) ? sanitize_text_field( wp_unslash( $_GET['events_type'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'page' => isset( $_GET['events_p'] )    ? max( 1, (int) wp_unslash( $_GET['events_p'] ) )            : 1,  // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);
	}

	public static function filter_events( array $logs, array $f ) {
		$q = strtolower( $f['q'] );
		$t = strtolower( $f['type'] );
		return array_values( array_filter( $logs, static function ( $r ) use ( $q, $t ) {
			$type = strtolower( (string) ( $r['type'] ?? '' ) );
			$note = strtolower( (string) ( $r['note'] ?? '' ) );
			if ( '' !== $t && false === stripos( $type, $t ) ) {
				return false;
			}
			if ( '' !== $q && false === strpos( $type . ' ' . $note, $q ) ) {
				return false;
			}
			return true;
		} ) );
	}

	public static function hits_from_request() {
		return array(
			'q'    => isset( $_GET['hits_q'] )  ? sanitize_text_field( wp_unslash( $_GET['hits_q'] ) )  : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'ip'   => isset( $_GET['hits_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['hits_ip'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'm'    => isset( $_GET['hits_m'] )  ? strtoupper( sanitize_text_field( wp_unslash( $_GET['hits_m'] ) ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'page' => isset( $_GET['hits_p'] )  ? max( 1, (int) wp_unslash( $_GET['hits_p'] ) ) : 1, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);
	}

	public static function filter_hits( array $hits, array $f ) {
		$q  = strtolower( $f['q'] );
		$ip = strtolower( $f['ip'] );
		$m  = strtoupper( $f['m'] );
		return array_values( array_filter( $hits, static function ( $r ) use ( $q, $ip, $m ) {
			$R_ip   = strtolower( (string) ( $r['ip'] ?? '' ) );
			$R_m    = strtoupper( (string) ( $r['m'] ?? '' ) );
			$path   = (string) ( $r['path'] ?? ( $r['route'] ?? '' ) );
			$data_s = strtolower( wp_json_encode( $r['data'] ?? '' ) );

			if ( '' !== $ip && false === stripos( $R_ip, $ip ) ) {
				return false;
			}
			if ( '' !== $m && $R_m !== $m ) {
				return false;
			}
			if ( '' !== $q && false === strpos( strtolower( $path ) . ' ' . $data_s, $q ) ) {
				return false;
			}
			return true;
		} ) );
	}
}