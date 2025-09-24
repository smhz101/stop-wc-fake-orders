<?php
/**
 * Plugin Name: Stop WooCommerce Fake Orders
 *  Description: Edge gate + IP/CIDR allowlist + optional HMAC + Redis-backed IP/email rate limits/bans + REST abuse protection + JS cookie + honeypot + success-resets + admin UI + logs export + per-route exemptions + header bypass + optional CAPTCHA-after-soft-block + CIDR soft deny (429). Single file.
 * Version: 2.3.0
 * Author: Muzammil
 * Text Domain: stop-woocommerce-fake-orders
 * Domain Path: /languages
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

/** ===== Constants (safe defaults; can be overridden via wp-config.php) ===== */
if (!defined('SWFO_PREFIX')) define('SWFO_PREFIX', 'swfo_');
if (!defined('SWFO_SOFT_DENY_429')) define('SWFO_SOFT_DENY_429', true); // soft deny (429) for CIDR/country lists
// Redis auth/db constants (preferred for secrets; options UI also supported)
if (!defined('SWFO_USE_REDIS')) define('SWFO_USE_REDIS', false); // set true in wp-config for prod if phpredis is installed
if (!defined('SWFO_REDIS_AUTH')) define('SWFO_REDIS_AUTH', '');  // e.g. 'mySecretPass' (leave '' if none)
if (!defined('SWFO_REDIS_DB'))   define('SWFO_REDIS_DB', 0);     // e.g. 0..15


/**
 * Class SWFO_Opt
 *
 * Provides utility functions for the Stop WC Fake Orders plugin.
 */
 
/**
 * Generate a prefixed option key.
 *
 * @param string $n The option name to be prefixed.
 * @return string The prefixed option key.
 */
class SWFO_Opt { static function k($n){ return SWFO_PREFIX.$n; } }

/**
 * Main plugin class for Stop WC Fake Orders.
 *
 * Handles initialization and core functionality for the Stop WC Fake Orders plugin.
 */
class SWFO_Plugin {
	/**
	 * Holds the singleton instance of the class.
	 *
	 * @var self
	 */
	private static $inst;

	/**
	 * @var Redis|null $redis Instance of Redis client or null if not initialized.
	 * @var bool $use_redis Flag to indicate whether Redis should be used.
	 */
	private $redis=null, 
					$use_redis=false;

	/**
	 * Default plugin options.
	 *
	 * Associative array of option keys and their default values. These are written
	 * to the database on first run (see ensure_defaults()) and can be overridden
	 * via the admin UI or wp-config.php constants where noted.
	 *
	 * Keys:
	 * - 'api_keys' (array<string,string>): Map of key IDs to password_hash()'d API
	 *   keys used for S2S auth via the X-WC-API-Key header.
	 * - 'allowlist_cidrs' (string[]): IPv4/IPv6 CIDRs or plain IPs that bypass
	 *   most gates (partners, office ranges).
	 * - 'ua_denylist' (string[]): Case-insensitive substrings; if matched in the
	 *   User-Agent, the request is blocked.
	 * - 'required_cookie' (string): Name of the JS challenge cookie set on
	 *   checkout to prove a real browser (default 'swfo_js').
	 * - 'enable_js_challenge' (bool): If true, require the JS cookie for sensitive
	 *   actions (REST checkout/orders, form checkout).
	 * - 'enable_honeypot' (bool): If true, add/validate a hidden honeypot field on
	 *   checkout (REST + form).
	 * - 'enable_hmac' (bool): If true, require HMAC headers (X-WC-HMAC,
	 *   X-WC-Timestamp) when an API key is supplied.
	 * - 'hmac_secret' (string): Shared secret used to compute request signatures
	 *   when HMAC is enabled.
	 * - 'window_seconds' (int): Sliding window length in seconds for rate limits.
	 * - 'ip_rate_limit' (int): Max REST calls per IP per window (general gate).
	 * - 'email_rate_limit' (int): Max checkout attempts per billing email per
	 *   window.
	 * - 'logs_max' (int): Number of recent events to retain in the in-memory/Redis
	 *   queue.
	 * - 'use_redis' (bool): Whether to use phpredis for counters/logs. Can also be
	 *   forced via SWFO_USE_REDIS.
	 * - 'redis_host' (string): Redis host (default '127.0.0.1').
	 * - 'redis_port' (int): Redis port (default 6379).
	 * - 'redis_auth' (string): Optional Redis AUTH password. Prefer the
	 *   SWFO_REDIS_AUTH constant in wp-config.php for secrets.
	 * - 'redis_db' (int): Optional Redis database index (0..15). Prefer
	 *   SWFO_REDIS_DB constant.
	 * - 'log_to_error_log' (bool): If true, mirror events to PHP error_log.
	 * - 'webhook_url' (string): If non-empty, send JSON event payloads to this
	 *   URL asynchronously (non-blocking).
	 * - 'captcha_enabled' (bool): If true, enable simple math CAPTCHA on checkout
	 *   (REST + form).
	 * - 'captcha_after_soft_blocks' (int): Threshold of soft blocks before
	 *   CAPTCHA is enforced in REST (form always enforces when enabled).
	 * - 'bypass_tokens' (array<string,string>): Map of bypass token names to
	 *   tokens for trusted jobs via X-SWFO-Bypass header.
	 * - 'soft_deny_cidrs' (string[]): CIDRs that receive HTTP 429 (soft deny) to
	 *   discourage probing without revealing explicit blocking.
	 * - 'enable_api_hit_logging' (bool): Master switch for wp-json traffic logging.
	 * - 'api_hits_max' (int): Number of REST hit entries to keep (Redis list or
	 *   transient ring).
	 * - 'store_api_write_rate_limit' (int): Max write calls to Store API cart /
	 *   checkout per IP per window.
	 * - 'store_api_mode' (string): Store API protection mode: 'open',
	 *   'same-origin' (default), 'js-cookie', or 'api-key'.
	 * - 'store_api_rate_limit' (int): Max GET reads to Store API per IP per
	 *   window.
	 *
	 * @var array<string,mixed>
	 * @since 1.0.0
	 */
	private $defaults = [
		'api_keys'=>[],                 // [id => password_hash(key)]
		'allowlist_cidrs'=>[],          // [ '1.2.3.0/24', ... ]
		'ua_denylist'=>[],              // substrings
		'required_cookie'=>'swfo_js',   // JS challenge cookie
		'enable_js_challenge'=>true,
		'enable_honeypot'=>true,
		'enable_hmac'=>false,
		'hmac_secret'=>'',
		'window_seconds'=>60,
		'ip_rate_limit'=>50,            // per window
		'email_rate_limit'=>10,         // per window
		'logs_max'=>300,
		'use_redis'=>false,
		'redis_host'=>'127.0.0.1',
		'redis_port'=>6379,
		'redis_auth' => '',   // optional password
		'redis_db'   => 0,    // optional database index
		// Export/logging
		'log_to_error_log'=>false,
		'webhook_url'=>'',
		// CAPTCHA after N soft blocks (math captcha)
		'captcha_enabled'=>true,
		'captcha_after_soft_blocks'=>3,
		// Bypass header token for trusted S2S (distinct from API keys)
		'bypass_tokens'=>[],            // ['token_name' => 'plain-or-hash']
		// CIDR soft-deny (429), separate from allowlist
		'soft_deny_cidrs'=>[],          // returns 429 (not 403) to discourage probing
		// API hit logging
		'enable_api_hit_logging'=> true,  // master switch
		'api_hits_max'=> 1000,  // keep last N hits (Redis list or transient)
		// Store API hardening (GET reads)
		'store_api_write_rate_limit' => 60, // writes/window for /wc/store/cart|checkout (per IP)
		'store_api_mode' => 'same-origin', // 'open' | 'same-origin' | 'js-cookie' | 'api-key'
		'store_api_rate_limit' => 120,     // GETs/window for /wc/store/* (per IP)
	];

	/**
	 * Bootstrap the singleton instance and initialize plugin hooks.
	 *
	 * Creates the plugin instance on first call, runs {@see SWFO_Plugin::init()},
	 * and returns the same instance on subsequent calls.
	 *
	 * @since 1.0.0
	 *
	 * @return SWFO_Plugin The singleton plugin instance.
	 */
	static function boot() { 
		if( !self::$inst ) { 
			self::$inst = new self; 
			self::$inst->init(); 
		} 
		return self::$inst; 
	}

	/**
	 * Initialize the plugin by registering all WordPress hooks and filters.
	 *
	 * Responsibilities include:
	 * - Adding contextual help tabs for the plugin screen.
	 * - Showing core admin notices and ensuring default options exist.
	 * - Establishing a Redis connection (if enabled).
	 * - Registering the admin menu and admin-post handlers (API key/bypass CRUD).
	 * - Enforcing REST gating for WooCommerce endpoints.
	 * - Hardening checkout (honeypot, JS cookie, CAPTCHA) and performing success resets.
	 * - Attempting safe insertion of recommended constants into wp-config.php.
	 * - Adding the Settings link on the Plugins list row.
	 * - Logging REST requests early for observability.
	 * - Providing CSV export/clear actions for API hit logs.
	 * - Enqueuing admin assets and exposing AJAX endpoints for live Events/API Hits.
	 *
	 * Hooks added:
	 * - Actions: load-woocommerce_page_swfo, admin_notices, admin_init, admin_menu,
	 *   admin_post_swfo_generate_key, admin_post_swfo_delete_key, admin_post_swfo_add_bypass,
	 *   admin_post_swfo_delete_bypass, woocommerce_after_order_notes, woocommerce_checkout_process,
	 *   wp_enqueue_scripts, woocommerce_thankyou, woocommerce_order_status_processing,
	 *   woocommerce_order_status_completed, admin_enqueue_scripts, wp_ajax_swfo_get_events,
	 *   wp_ajax_swfo_get_hits.
	 * - Filters: rest_request_before_callbacks (gate), rest_request_before_callbacks (hit logger),
	 *   plugin_action_links_{plugin_basename(__FILE__)}.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function init(){
		// Add contextual help tabs for this admin screen
		add_action('load-woocommerce_page_swfo', [$this,'add_help_tabs']);
		
		// Core hooks
		add_action('admin_notices', [$this,'maybe_wc_notice']);
		add_action('admin_init', [$this,'ensure_defaults']);
		add_action( 'admin_init', [$this, 'add_privacy_policy_content']);

		$this->setup_redis();

		// Admin UI
		add_action('admin_menu', [$this,'menu']);
		add_action('admin_post_swfo_generate_key', [$this,'handle_generate_key']);
		add_action('admin_post_swfo_delete_key', [$this,'handle_delete_key']);
		add_action('admin_post_swfo_add_bypass', [$this,'handle_add_bypass']);
		add_action('admin_post_swfo_delete_bypass', [$this,'handle_delete_bypass']);

		// REST gating
		add_filter('rest_request_before_callbacks', [$this,'rest_gate'], 10, 3);

		// Checkout hardening
		add_action('woocommerce_after_order_notes', [$this,'checkout_fields']);
		add_action('woocommerce_checkout_process', [$this,'checkout_validate']);
		add_action('wp_enqueue_scripts', [$this,'enqueue_js']);

		// Success resets: when order paid/placed successfully, reset counters for buyer
		add_action('woocommerce_thankyou', [$this,'success_reset_by_order_id']);
		add_action('woocommerce_order_status_processing', [$this,'success_reset_by_order_obj']);
		add_action('woocommerce_order_status_completed', [$this,'success_reset_by_order_obj']);

		// Settings link
		add_filter('plugin_action_links_'.plugin_basename(__FILE__), [$this,'links']);

		// Log ALL wp-json (REST) hits early, before gating decisions (runs on every REST request)
		add_filter('rest_request_before_callbacks', [$this,'rest_hit_logger'], 1, 3);

		// Admin actions for API hits (CSV export / clear)
		add_action('admin_post_swfo_export_hits', [$this,'handle_export_api_hits']);
		add_action('admin_post_swfo_clear_hits',  [$this,'handle_clear_api_hits']);

		// Admin assets + AJAX endpoints
		add_action( 'admin_enqueue_scripts', [ $this, 'admin_enqueue_assets' ] );
		add_action( 'wp_ajax_swfo_get_events', [ $this, 'ajax_get_events' ] );
		add_action( 'wp_ajax_swfo_get_hits',   [ $this, 'ajax_get_hits' ] );

		add_action( 'plugins_loaded', [ $this, 'load_textdomain' ] );
	}

	function add_privacy_policy_content() {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
				$content = __( 'Stop WooCommerce Fake Orders may log REST API request metadata (IP address, user agent, request path, method, and masked parameters) for rate-limiting and security diagnostics. Logging can be disabled in the plugin settings. Data is stored transiently in the database or Redis and is pruned to the configured limits. If a webhook is configured, minimal event payloads are sent to that endpoint.', 'stop-woocommerce-fake-orders' );
				wp_add_privacy_policy_content( __( 'Stop WooCommerce Fake Orders', 'stop-woocommerce-fake-orders' ), wp_kses_post( "<p>{$content}</p>" ) );
		}
	}

	/**
	 * Initialize the Redis client if enabled and available.
	 *
	 * Checks if Redis usage is enabled via options or the SWFO_USE_REDIS constant,
	 * verifies the `redis` PHP extension is loaded, and attempts to connect to the
	 * configured Redis server. On success, assigns the connected client to
	 * `$this->redis` and sets `$this->use_redis` to true. On failure, logs an error
	 * message and leaves `$this->use_redis` false to fall back to transients.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'stop-woocommerce-fake-orders', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' ); 
	}

	/**
	 * Enqueue admin-side assets and bootstrap live (AJAX) polling for the plugin screen.
	 *
	 * Registers a lightweight inline script handle and localizes runtime data
	 * (AJAX URL, nonce, polling interval, and strings), then injects the polling
	 * module via {@see self::admin_polling_js()} for the "Recent Events" and
	 * "API Hits" tabs. Runs only on the SWFO settings screen.
	 *
	 * Security:
	 * - Nonce `swfo_admin` is provided for authenticated AJAX requests.
	 *
	 * @since 2.0.0
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public function admin_enqueue_assets( $hook ) {
		if ( 'woocommerce_page_swfo' !== $hook ) {
			return;
		}

		wp_register_script(
    	'swfo-chart',
    	plugins_url( 'assets/js/chart.min.js', __FILE__ ),
    	array(),
    	'4.5.0',
    	true
		);

		// Lightweight inline module (no external file to keep single-file plugin)
		wp_register_script( 'swfo-admin', false, [ 'jquery', 'swfo-chart' ], '2.1.0', true );

		wp_localize_script(
			'swfo-admin',
			'SWFOData',
			[
				'ajax_url'      => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'swfo_admin' ),
				'poll_interval' => 7000, // ms
				'i18n'          => [
					'banConfirm' => __( 'Clear all API hits?', 'default' ), // (example—reuse if needed)
				],
			]
		);

		wp_add_inline_script( 'swfo-admin', $this->admin_polling_js() );
		wp_enqueue_script( 'swfo-admin' );
	}

	/**
	 * Returns the polling JS (kept here to avoid separate file).
	 */
	private function admin_polling_js() {
		return <<<JS
	(function($){
		'use strict';

		var lastEventTs = 0;
		var lastHitTs   = 0;
		var timer       = null;

		function activeTab(){
			var \$a = $('.nav-tab.nav-tab-active');
			return \$a.length ? \$a.data('tab') : 'status';
		}

		function start(){
			stop();
			timer = setInterval(fetchUpdates, SWFOData.poll_interval || 7000);
		}

		function stop(){
			if (timer) { clearInterval(timer); timer = null; }
		}

		function fetchUpdates(){
			var tab = activeTab();
			if (tab === 'events') {
				getJSON('swfo_get_events', lastEventTs, function(items){
					if (!items || !items.length) { return; }
					lastEventTs = Math.max.apply(null, items.map(function(i){ return i.t || 0; }));
					appendEvents(items);
				});
			} else if (tab === 'apihits') {
				getJSON('swfo_get_hits', lastHitTs, function(items){
					if (!items || !items.length) { return; }
					lastHitTs = Math.max.apply(null, items.map(function(i){ return i.t || 0; }));
					appendHits(items);
				});
			}
		}

		function getJSON(action, since, cb){
			$.ajax({
				url: SWFOData.ajax_url,
				method: 'GET',
				dataType: 'json',
				data: {
					action: action,
					since: since || 0,
					_ajax_nonce: SWFOData.nonce
				}
			}).done(function(resp){
				if (resp && resp.success && resp.data && resp.data.items) {
					cb(resp.data.items);
				}
			});
		}

		// --- DOM helpers (prepend newest-first, cap table length a bit) ---
		function appendEvents(items){
			var \$tbody = $('#swfo-events-body');
			if (!\$tbody.length) { return; }
			// Items already newest-first; prepend in reverse so the very newest ends up on top
			items.slice().reverse().forEach(function(row){
				var dt = row.t ? formatTs(row.t) : '';
				var type = esc(row.type || '');
				var note = esc(row.note || '');
				var \$tr = $('<tr/>')
					.append($('<td/>').text(dt))
					.append($('<td/>').text(type))
					.append($('<td/>').text(note));
				\$tbody.prepend(\$tr);
			});
			trimRows(\$tbody, 500);
		}

		function appendHits(items){
			var \$tbody = $('#swfo-hits-body');
			if (!\$tbody.length) { return; }
			items.slice().reverse().forEach(function(h){
				var dt = h.t ? formatTs(h.t) : '';
				var ip = esc(h.ip || '');
				var m  = esc((h.m || '').toUpperCase());
				var p  = esc(h.path || h.route || '');
				var d  = (typeof h.data === 'object') ? JSON.stringify(h.data).slice(0,3000) : String(h.data || '');
				var \$tr = $('<tr/>')
					.append($('<td/>').text(dt))
					.append($('<td/>').append($('<code/>').text(ip)))
					.append($('<td/>').text(m))
					.append($('<td/>').append($('<code/>').text(p)))
					.append($('<td/>').append($('<code style="white-space:pre-wrap;word-break:break-word;display:block;max-height:6.5em;overflow:auto;"/>').text(d)));
				\$tbody.prepend(\$tr);
			});
			trimRows(\$tbody, 500);
		}

		function trimRows(\$tbody, limit){
			var \$rows = \$tbody.find('tr');
			if (\$rows.length > limit) {
				\$rows.slice(limit).remove();
			}
		}

		function formatTs(t){
			var d = new Date(t * 1000);
			var pad = function(n){ return n<10 ? '0'+n : n; };
			return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) + ' ' +
						pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
		}

		function esc(s){
			// jQuery will handle text() escaping; this is for non-jQuery string contexts if needed
			return String(s);
		}

		// attach listeners to tabs to start/stop polling
		$(document).on('click', '.nav-tab', function(){
			// Defer to allow your existing tab switcher to run
			setTimeout(function(){
				var tab = activeTab();
				if (tab === 'events' || tab === 'apihits') { start(); } else { stop(); }
			}, 0);
		});

		// initialize on load
		$(function(){
			// derive initial last timestamps from first row if needed (optional)
			var \$firstEvent = $('#swfo-events-body tr:first td:first');
			if (\$firstEvent.length) { lastEventTs = Math.floor(Date.now()/1000); }
			var \$firstHit = $('#swfo-hits-body tr:first td:first');
			if (\$firstHit.length) { lastHitTs = Math.floor(Date.now()/1000); }

			var tab = activeTab();
			if (tab === 'events' || tab === 'apihits') { start(); }
		});

		$(window).on('beforeunload', stop);
	})(jQuery);
	JS;
	}

	/**
	 * AJAX: Fetch "Recent Events" items for live admin updates.
	 *
	 * Expects authenticated requests from the SWFO settings screen and returns a JSON
	 * payload containing recent log entries (optionally filtered by a UNIX timestamp).
	 *
	 * Request:
	 * - Capability: Current user must have `manage_options`.
	 * - Nonce: `swfo_admin` (sent as `_ajax_nonce`).
	 * - Query param `since` (optional, int): If provided, only events with `t` > `since`
	 *   are returned. Useful for incremental polling.
	 *
	 * Response (on success):
	 * - `items` (array): Log entries, newest-first as stored, each with keys like `t`, `type`, `note`.
	 * - `server_time` (int): Current server UNIX timestamp to be used as the next `since` cursor.
	 *
	 * HTTP Status:
	 * - 403 on capability failure.
	 * - 200 with `success: true` on success, `success: false` on nonce/capability failure.
	 *
	 * @since 2.0.0
	 *
	 * @return void Sends a JSON response and exits.
	 */
	public function ajax_get_events() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'forbidden' ], 403 );
		}
		check_ajax_referer( 'swfo_admin', '_ajax_nonce' );

		$since = isset( $_GET['since'] ) ? intval( $_GET['since'] ) : 0;

		$logs = $this->logs_get();
		if ( $since > 0 ) {
			$logs = array_values(
				array_filter(
					(array) $logs,
					static function( $r ) use ( $since ) {
						$t = isset( $r['t'] ) ? (int) $r['t'] : 0;
						return ( $t > $since );
					}
				)
			);
		}

		wp_send_json_success(
			[
				'items'       => $logs,
				'server_time' => time(),
			]
		);
	}

	/**
	 * AJAX: Fetch "API Hits" (wp-json traffic) for live admin updates.
	 *
	 * Expects authenticated requests from the SWFO settings screen and returns a JSON
	 * payload containing recent API-hit entries, optionally filtered by a UNIX
	 * timestamp cursor.
	 *
	 * Request:
	 * - Capability: Current user must have `manage_options`.
	 * - Nonce: `swfo_admin` (sent as `_ajax_nonce`).
	 * - Query param `since` (optional, int): If provided, only hits with `t` > `since`
	 *   are returned. Use the returned `server_time` as the next cursor when polling.
	 *
	 * Response (on success):
	 * - `items` (array): API-hit entries (newest first), each typically including:
	 *   `t` (int, timestamp), `ip` (string), `m` (HTTP method), `path` (string),
	 *   `route` (string), `ua` (string), and `data` (array|string; masked/truncated).
	 * - `server_time` (int): Current server UNIX timestamp to use for subsequent polls.
	 *
	 * HTTP Status:
	 * - 403 on capability failure.
	 * - 200 with `success: true` on success (or `success: false` on nonce failure).
	 *
	 * @since 2.0.0
	 *
	 * @return void Sends a JSON response and exits.
	 */
	public function ajax_get_hits() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'forbidden' ], 403 );
		}
		check_ajax_referer( 'swfo_admin', '_ajax_nonce' );

		$since = isset( $_GET['since'] ) ? intval( $_GET['since'] ) : 0;

		$hits = $this->api_hits_get();
		if ( $since > 0 ) {
			$hits = array_values(
				array_filter(
					(array) $hits,
					static function( $r ) use ( $since ) {
						$t = isset( $r['t'] ) ? (int) $r['t'] : 0;
						return ( $t > $since );
					}
				)
			);
		}

		wp_send_json_success(
			[
				'items'       => $hits,
				'server_time' => time(),
			]
		);
	}

	/**
	 * Register contextual Help Tabs for the SWFO settings screen.
	 *
	 * Adds multiple tabs (Overview, Rate Limiting, Edge Gate & Identity, Browser
	 * Challenges, Allow/Deny Lists, Logs & Export) plus a tips sidebar to the
	 * WooCommerce → Stop Fake Orders admin screen. Runs only when the current
	 * screen is `woocommerce_page_swfo`.
	 *
	 * @since 1.9.0
	 *
	 * @global WP_Screen $current_screen Current admin screen object.
	 * @return void
	 */
	public function add_help_tabs(){
		$screen = get_current_screen();
		if ( ! $screen || $screen->id !== 'woocommerce_page_swfo' ) return;

		$screen->add_help_tab([
			'id'      => 'swfo_overview',
			'title'   => __('Overview','stop-woocommerce-fake-orders'),
			'content' =>
				'<p><strong>Stop WooCommerce Fake Orders</strong> adds edge gating, rate limiting, and checkout hardening to reduce spam/fraud orders while keeping real buyers unblocked.</p>'.
				'<ul>'.
				'<li><strong>Edge Gate</strong>: API key, allowlist, optional HMAC.</li>'.
				'<li><strong>Rate Limits</strong>: Redis-backed counters (IP/email) with transient fallback.</li>'.
				'<li><strong>Checkout Hardening</strong>: JS cookie + honeypot; optional CAPTCHA after repeated soft blocks.</li>'.
				'<li><strong>Logs</strong>: Lightweight recent events; optional export to error_log or webhook.</li>'.
				'</ul>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_limits',
			'title' => __('Rate Limiting','stop-woocommerce-fake-orders'),
			'content' =>
				'<p><strong>Window (sec)</strong> defines the sliding window length. '.
				'<strong>IP requests/window</strong> caps how many REST calls per IP. '.
				'<strong>Email submits/window</strong> caps how many order attempts per email.</p>'.
				'<p>With Redis enabled, counters are scalable (INCR/EXPIRE). Without Redis, transients approximate the same behavior.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_gates',
			'title' => __('Edge Gate & Identity','stop-woocommerce-fake-orders'),
			'content' =>
				'<p>Use <code>X-WC-API-Key</code> for server-to-server requests. Keys are stored hashed. '.
				'Optional HMAC (<code>X-WC-HMAC</code>, <code>X-WC-Timestamp</code>) deters key replay within ±5 minutes. '.
				'Bypass tokens (<code>X-SWFO-Bypass</code>) are for trusted backend jobs to skip browser checks.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_browser',
			'title' => __('Browser Challenges','stop-woocommerce-fake-orders'),
			'content' =>
				'<p><strong>JS cookie</strong> verifies a real browser is present. <strong>Honeypot</strong> blocks naive bots. '.
				'Enable <strong>CAPTCHA</strong> only after repeated soft blocks to minimize friction for legit buyers.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_lists',
			'title' => __('Allow/Deny Lists','stop-woocommerce-fake-orders'),
			'content' =>
				'<p><strong>Allowlist CIDRs</strong> fully bypass protections (trusted partners). '.
				'<strong>Soft-deny CIDRs</strong> respond with HTTP 429 (not 403) to discourage probing. '.
				'<strong>UA denylist</strong> rejects known bad user agents.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_telemetry',
			'title' => __('Logs & Export','stop-woocommerce-fake-orders'),
			'content' =>
				'<p>Recent events are kept in memory/Redis (no DB bloat). '.
				'Enable <strong>error_log</strong> export or set a <strong>Webhook URL</strong> to stream JSON events to your SIEM.</p>'
		]);

		$screen->set_help_sidebar(
			'<p><strong>Tips</strong></p>'.
			'<p>Start with conservative limits, observe logs, then tighten gradually.</p>'.
			'<p>Whitelist your own CI/CD or monitoring IPs to avoid false positives.</p>'
		);
	}

	/**
	 * Output an admin notice if WooCommerce is not active.
	 *
	 * Displays a dismissible warning on admin screens (for users with the
	 * `manage_options` capability) indicating that the plugin works best when
	 * WooCommerce is active.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function maybe_wc_notice(){
		if( is_admin() && current_user_can('manage_options') && !class_exists('WooCommerce') ){
			echo '<div class="notice notice-warning"><p><strong>Stop WooCommerce Fake Orders</strong> works best with WooCommerce active.</p></div>';
		}
	}

	/**
	 * Ensure plugin options are initialized with default values.
	 *
	 * On first run (when the `configured` flag is absent), iterates through the
	 * `$this->defaults` map and seeds any missing options using `update_option()`.
	 * Finally sets the `configured` flag so this initialization runs only once.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function ensure_defaults(){
		if(!get_option(SWFO_Opt::k('configured'))){
			foreach($this->defaults as $k=>$v) if(false===get_option(SWFO_Opt::k($k))) update_option(SWFO_Opt::k($k), $v);
			update_option(SWFO_Opt::k('configured'),1);
		}
	}

	/**
	 * Initialize the Redis client (phpredis) if enabled and available.
	 *
	 * Determines whether Redis should be used from plugin options or constants,
	 * validates the `redis` PHP extension, and attempts to connect using the
	 * configured host/port with an optional AUTH and DB selection. On success,
	 * assigns the connected client to `$this->redis` and flips `$this->use_redis`
	 * to true. On any failure, logs a concise error via `error_log()` and keeps
	 * transient fallback by leaving `$this->use_redis` false.
	 *
	 * Notes:
	 * - Honors `SWFO_USE_REDIS`, `SWFO_REDIS_AUTH`, and `SWFO_REDIS_DB` constants
	 *   (preferred for secrets) while still allowing settings from the options UI.
	 * - Uses a short connection timeout and verifies connectivity with `PING`.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function setup_redis(){
		$this->redis = null;
		$this->use_redis = false;

		$opt_use = (defined('SWFO_USE_REDIS') && SWFO_USE_REDIS) || (bool)get_option(SWFO_Opt::k('use_redis'), false);
		if(!$opt_use || !extension_loaded('redis')) return;

		$host = get_option(SWFO_Opt::k('redis_host'),'127.0.0.1');
		$port = intval(get_option(SWFO_Opt::k('redis_port'),6379));
		$auth = defined('SWFO_REDIS_AUTH') ? SWFO_REDIS_AUTH : '';
		$auth = $auth !== '' ? $auth : (string)get_option(SWFO_Opt::k('redis_auth'),'');
		$db   = defined('SWFO_REDIS_DB') ? (int)SWFO_REDIS_DB : (int)get_option(SWFO_Opt::k('redis_db'),0);

		try{
			$r = new Redis();
			$r->connect($host, $port, 1.0, null, 0, 0.0); // short timeout
			if($auth !== ''){
				if(!$r->auth($auth)) throw new Exception('Redis AUTH failed');
			}
			if($db > 0){
				if(!$r->select($db)) throw new Exception('Redis SELECT DB failed');
			}
			// quick ping to confirm
			if( $r->ping() !== '+PONG' ) throw new Exception('Redis PING failed');

			$this->redis = $r;
			$this->use_redis = true;
		}catch(\Throwable $e){
			$this->redis = null;
			$this->use_redis = false;
			error_log('SWFO Redis disabled: '.$e->getMessage());
		}
	}

	/**
	 * Register the plugin’s admin submenu under the WooCommerce menu.
	 *
	 * Adds a "Stop Fake Orders" submenu page (slug: `swfo`) that is visible to
	 * users with the `manage_options` capability and renders the main settings
	 * screen via {@see self::admin_page()}.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function menu(){
		add_submenu_page('woocommerce','Stop Fake Orders','Stop Fake Orders','manage_options','swfo',[$this,'admin_page']);
	}

	/**
	 * Render the plugin’s main admin screen and handle settings saves.
	 *
	 * Outputs the single-page settings UI under WooCommerce → Stop Fake Orders,
	 * including tabbed sections (Status, Rate Limits, Edge Gate & Identity,
	 * Allow/Deny, Browser Challenges, Redis, Logs & Export, Recent Events,
	 * API Hits, Store API). When the settings form is submitted, verifies the
	 * nonce, persists options via {@see self::save_settings()}, reinitializes
	 * Redis via {@see self::setup_redis()}, and redirects back to the active tab
	 * using {@see self::tab_url()} to avoid resubmission.
	 *
	 * The screen also renders summary charts, filtered/paginated “Recent Events”
	 * and “API Hits” tables (with masked sensitive fields), and action buttons
	 * for exporting and clearing API hits.
	 *
	 * Capability required: `manage_options`.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function admin_page(){
		if(!current_user_can('manage_options')) return;

		// Save + feedback (redirect back to current tab)
		if ( isset($_POST['swfo_save']) && check_admin_referer('swfo_save', 'swfo_nonce') ) {
			$this->save_settings();
			$this->setup_redis();
			$tab = isset($_POST['swfo_tab']) ? sanitize_text_field( wp_unslash( $_POST['swfo_tab'] ) ) : 'status';
			wp_safe_redirect( $this->tab_url($tab) ); // preserves ?swfo_tab=... and #...
			exit;
		}

		$keys   = get_option(SWFO_Opt::k('api_keys'),[]);
		$bypass = get_option(SWFO_Opt::k('bypass_tokens'),[]);
		$logs   = $this->logs_get();

		// Simple helper to print tab header
		$tabs = [
			'status'   => 'Status',
			'limits'   => 'Rate Limits',
			'edge'     => 'Edge Gate & Identity',
			'lists'    => 'Allow / Deny',
			'browser'  => 'Browser Challenges',
			'redis'    => 'Redis',
			'logging'  => 'Logs & Export',
			'events'   => 'Recent Events',
			'apihits'  => 'API Hits',
			'storeapi' => 'Store API',
		];
		?>
		<div class="wrap">
			<h1>Stop WooCommerce Fake Orders</h1>
			<p class="description" style="max-width:900px">Harden your store against spam & abusive automation. Use tabs to navigate.</p>

			<!-- Native WP nav tabs -->
			<h2 class="nav-tab-wrapper">
				<?php foreach($tabs as $slug => $label): ?>
					<a href="#<?php echo esc_attr($slug); ?>" class="nav-tab" data-tab="<?php echo esc_attr($slug); ?>">
						<?php echo esc_html($label); ?>
					</a>
				<?php endforeach; ?>
			</h2>

			<form method="post" action="<?php echo esc_url( admin_url('admin.php?page=swfo') ); ?>" style="max-width:1100px;">
				<?php wp_nonce_field('swfo_save', 'swfo_nonce'); ?>
				<input type="hidden" name="swfo_save" value="1">
  			<input type="hidden" name="swfo_tab" id="swfo_tab" value="">

				<style>
					/* Minimal, native-looking: panels hidden by default */
					.swfo-tab-panel{display:none}
					.swfo-tab-panel.is-active{display:block}
					.swfo-two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
					@media (max-width: 1000px){ .swfo-two-col{grid-template-columns:1fr} }
				</style>

				<!-- STATUS -->
				<div id="swfo-panel-status" class="swfo-tab-panel">
					<h2 class="title">Status</h2>

					<?php
						$ev = array_slice($logs, 0, 100);
						$byType = [];
						foreach ($ev as $e) { $t = $e['type'] ?? 'other'; $byType[$t] = ($byType[$t] ?? 0) + 1; }
						ksort($byType);

						// hits/hour (last 24h)
						$hitsAll = $this->api_hits_get();
						$now = time();
						$perHour = array_fill(0, 24, 0);
						foreach ($hitsAll as $h){
							$dt = (int) ($h['t'] ?? 0);
							if ($dt >= $now - 24*3600) {
								$idx = 23 - (int) floor(($now - $dt)/3600);
								if ($idx>=0 && $idx<24) $perHour[$idx]++;
							}
						}
						?>
						<h3 style="margin-top:24px">Activity</h3>
						<div style="max-width:900px;display:grid;grid-template-columns:1fr 1fr;gap:18px">
							<canvas id="swfoTypes"></canvas>
							<canvas id="swfoHits"></canvas>
						</div>
						<script>
						(function(){
							function load(fn){ if (window.Chart) return fn(); 
								var s=document.createElement('script'); s.src='https://cdn.jsdelivr.net/npm/chart.js'; s.onload=fn; document.head.appendChild(s); }
							load(function(){
								new Chart(document.getElementById('swfoTypes').getContext('2d'), {
									type:'bar',
									data:{ labels: <?php echo wp_json_encode(array_keys($byType)); ?>,
										datasets:[{ label:'Events (last 100)', data: <?php echo wp_json_encode(array_values($byType)); ?> }] },
									options:{ responsive:true, plugins:{ legend:{display:false} } }
								});
								new Chart(document.getElementById('swfoHits').getContext('2d'), {
									type:'line',
									data:{ labels: <?php echo wp_json_encode(range(1,24)); ?>,
										datasets:[{ label:'REST hits (last 24h)', data: <?php echo wp_json_encode($perHour); ?>, tension:0.2 }] },
									options:{ responsive:true, plugins:{ legend:{display:false} } }
								});
							});
						})();
						</script>

					<table class="widefat striped" style="max-width:900px">
						<tbody>
							<tr>
								<th style="width:240px;">Redis</th>
								<td>
									<?php if($this->use_redis && $this->redis): ?>
										<span class="dashicons dashicons-yes"></span> Connected
										<code><?php echo esc_html(get_option(SWFO_Opt::k('redis_host'),'127.0.0.1').':'.get_option(SWFO_Opt::k('redis_port'),6379)); ?></code>
										<?php if(defined('SWFO_REDIS_DB')): ?> (DB <?php echo intval(SWFO_REDIS_DB); ?>)<?php else: ?> (DB <?php echo intval(get_option(SWFO_Opt::k('redis_db'),0)); ?>)<?php endif; ?>
									<?php else: ?>
										<span class="dashicons dashicons-warning"></span> Not in use (falling back to transients)
									<?php endif; ?>
								</td>
							</tr>
							<tr><th>Window / Limits</th>
								<td>
									Window: <code><?php echo intval(get_option(SWFO_Opt::k('window_seconds'),60)); ?>s</code>,
									IP: <code><?php echo intval(get_option(SWFO_Opt::k('ip_rate_limit'),50)); ?>/window</code>,
									Email: <code><?php echo intval(get_option(SWFO_Opt::k('email_rate_limit'),10)); ?>/window</code>,
									Store GET: <code><?php echo intval(get_option(SWFO_Opt::k('store_api_rate_limit'),120)); ?>/window</code>
								</td>
							</tr>
							<tr><th>Modes</th>
								<td>
									HMAC: <code><?php echo get_option(SWFO_Opt::k('enable_hmac'),false)?'on':'off'; ?></code>,
									JS Cookie: <code><?php echo get_option(SWFO_Opt::k('enable_js_challenge'),true)?'on':'off'; ?></code>,
									Honeypot: <code><?php echo get_option(SWFO_Opt::k('enable_honeypot'),true)?'on':'off'; ?></code>,
									Store API mode: <code><?php echo esc_html(get_option(SWFO_Opt::k('store_api_mode'),'same-origin')); ?></code>
								</td>
							</tr>
							<tr><th>Queues</th>
								<td>
									Events kept: <code><?php echo intval(get_option(SWFO_Opt::k('logs_max'),300)); ?></code>,
									API hits kept: <code><?php echo intval(get_option(SWFO_Opt::k('api_hits_max'),1000)); ?></code>
								</td>
							</tr>
						</tbody>
					</table>
					<p class="description">Tip: if you enable Redis and set auth/db, counters and logs will scale better under load.</p>
				</div>

				<!-- RATE LIMITS -->
				<div id="swfo-panel-limits" class="swfo-tab-panel">
					<h2 class="title">Rate Limits</h2>
					<p class="description">Caps how often clients can hit sensitive routes. Start moderate, then tune.</p>
					<table class="form-table">
						<tr>
							<th scope="row">Window (seconds)</th>
							<td>
								<input type="number" name="window_seconds" value="<?php echo esc_attr(get_option(SWFO_Opt::k('window_seconds'),60)); ?>" min="10" step="1">
								<p class="description">Length of sliding window (default 60s).</p>
							</td>
						</tr>
						<tr>
							<th scope="row">IP requests per window</th>
							<td>
								<input type="number" name="ip_rate_limit" value="<?php echo esc_attr(get_option(SWFO_Opt::k('ip_rate_limit'),50)); ?>" min="5" step="1">
								<p class="description">Max REST calls allowed from one IP within the window before 429.</p>
							</td>
						</tr>
						<tr>
							<th scope="row">Email submits per window</th>
							<td>
								<input type="number" name="email_rate_limit" value="<?php echo esc_attr(get_option(SWFO_Opt::k('email_rate_limit'),10)); ?>" min="1" step="1">
								<p class="description">Max checkout attempts per email within the window.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- EDGE GATE & IDENTITY -->
				<div id="swfo-panel-edge" class="swfo-tab-panel">
					<h2 class="title">Edge Gate &amp; Identity</h2>
					<p class="description">Authenticate server-to-server calls. Public shoppers are not asked for keys.</p>

					<p>
						<a class="button" href="<?php echo esc_url(admin_url('admin-post.php?action=swfo_generate_key')); ?>">Generate API Key</a>
						<span class="description">Use header <code>X-WC-API-Key</code>. Key is shown once, stored hashed.</span>
					</p>
					<?php if($k = get_transient('swfo_last_key')): ?>
						<div class="inline notice notice-success"><p><strong>New API key:</strong> <code><?php echo esc_html($k); ?></code> — copy now.</p></div>
					<?php endif; ?>

					<table class="widefat striped" style="margin-top:10px;">
						<thead><tr><th>Key ID</th><th>Hash (short)</th><th>Action</th></tr></thead><tbody>
						<?php if(empty($keys)): ?>
							<tr><td colspan="3"><em>No API keys yet.</em></td></tr>
						<?php else: foreach($keys as $id=>$hash): ?>
							<tr>
								<td><?php echo esc_html($id); ?></td>
								<td><code><?php echo esc_html(substr($hash,0,14)); ?>…</code></td>
								<td><a class="button-link delete" href="<?php echo esc_url( wp_nonce_url(admin_url('admin-post.php?action=swfo_delete_key&id='.$id),'swfo_del_key') ); ?>">Delete</a></td>
							</tr>
						<?php endforeach; endif; ?>
						</tbody>
					</table>

					<h3>Signed Requests (HMAC)</h3>
					<table class="form-table">
						<tr>
							<th>Enable HMAC</th>
							<td>
								<label><input type="checkbox" name="enable_hmac" <?php checked(get_option(SWFO_Opt::k('enable_hmac'),false)); ?>> Require signed requests</label>
								<p class="description">Clients must send <code>X-WC-HMAC</code> and <code>X-WC-Timestamp</code> (±5 min).</p>
							</td>
						</tr>
						<tr>
							<th>HMAC secret</th>
							<td>
								<input type="text" name="hmac_secret" style="width:40%" value="<?php echo esc_attr(get_option(SWFO_Opt::k('hmac_secret'),'')); ?>">
								<p class="description">Signing string: <code>METHOD|ROUTE|BODY|TIMESTAMP</code>.</p>
							</td>
						</tr>
					</table>

					<h3>Bypass Tokens (trusted jobs)</h3>
					<p class="description">Header <code>X-SWFO-Bypass</code> lets approved backend jobs skip browser checks.</p>
					<table class="widefat striped">
						<thead><tr><th>Name</th><th>Token (short)</th><th>Action</th></tr></thead><tbody>
						<?php if(empty($bypass)): ?>
							<tr><td colspan="3"><em>No bypass tokens.</em></td></tr>
						<?php else: foreach($bypass as $n=>$t): ?>
							<tr>
								<td><?php echo esc_html($n); ?></td>
								<td><code><?php echo esc_html(substr($t,0,10)); ?>…</code></td>
								<td><a class="button-link delete" href="<?php echo esc_url( wp_nonce_url(admin_url('admin-post.php?action=swfo_delete_bypass&name='.$n),'swfo_del_bp') ); ?>">Delete</a></td>
							</tr>
						<?php endforeach; endif; ?>
						</tbody>
					</table>
					<p>
						<input type="text" name="bp_name" placeholder="name">
						<input type="text" name="bp_token" placeholder="token (blank = auto-generate)">
						<?php wp_nonce_field('swfo_add_bypass'); ?>
						<button class="button" formaction="<?php echo esc_url(admin_url('admin-post.php?action=swfo_add_bypass')); ?>">Add bypass</button>
					</p>
				</div>

				<!-- ALLOW / DENY -->
				<div id="swfo-panel-lists" class="swfo-tab-panel">
					<h2 class="title">Allow / Deny Lists</h2>
					<p class="description">Control which networks are fully trusted or gently discouraged.</p>
					<table class="form-table">
						<tr>
							<th>Allowlist CIDRs</th>
							<td>
								<textarea name="allowlist_cidrs" rows="4" cols="70"><?php echo esc_textarea(implode("\n",(array)get_option(SWFO_Opt::k('allowlist_cidrs'),[]))); ?></textarea>
								<p class="description">IPs/CIDRs here bypass most checks (partners, office ranges). One per line.</p>
							</td>
						</tr>
						<tr>
							<th>Soft-deny CIDRs (429)</th>
							<td>
								<textarea name="soft_deny_cidrs" rows="3" cols="70"><?php echo esc_textarea(implode("\n",(array)get_option(SWFO_Opt::k('soft_deny_cidrs'),[]))); ?></textarea>
								<p class="description">IPs/CIDRs receive <code>429 Too Many Requests</code> (not 403). One per line.</p>
							</td>
						</tr>
						<tr>
							<th>UA denylist</th>
							<td>
								<textarea name="ua_denylist" rows="3" cols="70"><?php echo esc_textarea(implode("\n",(array)get_option(SWFO_Opt::k('ua_denylist'),[]))); ?></textarea>
								<p class="description">Substrings of unwanted user agents (e.g. headless scrapers). One per line.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- BROWSER CHALLENGES -->
				<div id="swfo-panel-browser" class="swfo-tab-panel">
					<h2 class="title">Browser Challenges</h2>
					<p class="description">Lightweight friction for bots; minimal impact on humans.</p>
					<table class="form-table">
						<tr>
							<th>JS cookie challenge</th>
							<td>
								<label><input type="checkbox" name="enable_js_challenge" <?php checked(get_option(SWFO_Opt::k('enable_js_challenge'),true)); ?>> Enable</label>
								<p class="description">Sets a short-lived cookie via JavaScript to confirm a real browser.</p>
							</td>
						</tr>
						<tr>
							<th>Cookie name</th>
							<td>
								<input type="text" name="required_cookie" value="<?php echo esc_attr(get_option(SWFO_Opt::k('required_cookie'),'swfo_js')); ?>">
								<p class="description">Change only if another plugin conflicts with this cookie name.</p>
							</td>
						</tr>
						<tr>
							<th>Honeypot</th>
							<td>
								<label><input type="checkbox" name="enable_honeypot" <?php checked(get_option(SWFO_Opt::k('enable_honeypot'),true)); ?>> Enable</label>
								<p class="description">Hidden field catches naive bots filling every input.</p>
							</td>
						</tr>
						<tr>
							<th>CAPTCHA after N soft blocks</th>
							<td>
								<label><input type="checkbox" name="captcha_enabled" <?php checked(get_option(SWFO_Opt::k('captcha_enabled'),true)); ?>> Enable CAPTCHA</label>
								&nbsp;Threshold:
								<input type="number" name="captcha_after_soft_blocks" value="<?php echo esc_attr(get_option(SWFO_Opt::k('captcha_after_soft_blocks'),3)); ?>" style="width:80px">
								<p class="description">Simple math challenge appears only after repeated suspicious activity (soft blocks).</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- REDIS -->
				<div id="swfo-panel-redis" class="swfo-tab-panel">
					<h2 class="title">Redis</h2>
					<p class="description">Use Redis (phpredis) for accurate, scalable counters/bans. Recommended for production.</p>
					<table class="form-table">
						<tr>
							<th>Use Redis</th>
							<td>
								<label><input type="checkbox" name="use_redis" <?php checked((defined('SWFO_USE_REDIS') && SWFO_USE_REDIS) || get_option(SWFO_Opt::k('use_redis'),false)); ?>> Enable if extension is installed</label>
								<p class="description">If disabled or unavailable, the plugin falls back to WordPress transients.</p>
							</td>
						</tr>
						<tr>
							<th>Host</th>
							<td><input type="text" name="redis_host" value="<?php echo esc_attr(get_option(SWFO_Opt::k('redis_host'),'127.0.0.1')); ?>"></td>
						</tr>
						<tr>
							<th>Port</th>
							<td><input type="number" name="redis_port" value="<?php echo esc_attr(get_option(SWFO_Opt::k('redis_port'),6379)); ?>"></td>
						</tr>
						<tr>
							<th>Password</th>
							<td>
								<input type="password" name="redis_auth" autocomplete="new-password"
									value="<?php echo esc_attr( (defined('SWFO_REDIS_AUTH') && SWFO_REDIS_AUTH!=='') ? '********' : get_option(SWFO_Opt::k('redis_auth'), '') ); ?>">
								<p class="description">If your Redis requires AUTH. Prefer setting <code>SWFO_REDIS_AUTH</code> in <code>wp-config.php</code> for secrets.</p>
							</td>
						</tr>
						<tr>
							<th>DB index</th>
							<td>
								<input type="number" min="0" step="1" name="redis_db"
									value="<?php echo esc_attr( defined('SWFO_REDIS_DB') ? (int)SWFO_REDIS_DB : (int)get_option(SWFO_Opt::k('redis_db'),0) ); ?>">
								<p class="description">Select the logical database (0..15). Ignored if set via constant.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- LOGS & EXPORT -->
				<div id="swfo-panel-logging" class="swfo-tab-panel">
					<h2 class="title">Logs &amp; Export</h2>
					<p class="description">Lightweight in-memory/Redis queue; avoids DB bloat. Export to your SIEM if needed.</p>
					<table class="form-table">
						<tr>
							<th>Keep last N events</th>
							<td>
								<input type="number" name="logs_max" value="<?php echo esc_attr(get_option(SWFO_Opt::k('logs_max'),300)); ?>" min="50" step="10">
								<p class="description">Higher values show more history but use more memory.</p>
							</td>
						</tr>
						<tr>
							<th>Export to <code>error_log</code></th>
							<td>
								<label><input type="checkbox" name="log_to_error_log" <?php checked(get_option(SWFO_Opt::k('log_to_error_log'),false)); ?>> Enable</label>
								<p class="description">Writes events to PHP’s error log for quick tailing in ops environments.</p>
							</td>
						</tr>
						<tr>
							<th>Webhook URL</th>
							<td>
								<input type="url" name="webhook_url" style="width:60%" value="<?php echo esc_attr(get_option(SWFO_Opt::k('webhook_url'),'')); ?>">
								<p class="description">If set, events are POSTed as JSON (<code>{t,type,note}</code>) to your endpoint (non-blocking).</p>
							</td>
						</tr>
						<tr>
							<th>Enable API hit logging</th>
							<td>
								<label><input type="checkbox" name="enable_api_hit_logging" <?php checked(get_option(SWFO_Opt::k('enable_api_hit_logging'),true)); ?>> Enable</label>
								<p class="description">Turn off to stop collecting new entries (existing entries are kept).</p>
							</td>
						</tr>
						<tr>
							<th>Keep last N hits</th>
							<td>
								<input type="number" name="api_hits_max" value="<?php echo esc_attr(get_option(SWFO_Opt::k('api_hits_max'),1000)); ?>" min="100" step="100">
								<p class="description">Higher values keep more history (more memory in Redis/transients).</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- STORE API -->
				<div id="swfo-panel-storeapi" class="swfo-tab-panel">
					<h2 class="title">Store API (wc/store)</h2>
					<p class="description">Control public reads on <code>/wp-json/wc/store/*</code>. Default is <strong>Same-origin</strong> to block scrapers while allowing your front-end.</p>
					<table class="form-table">
						<tr>
							<th>Mode</th>
							<td>
								<?php $mode = get_option(SWFO_Opt::k('store_api_mode'),'same-origin'); ?>
								<fieldset>
									<label><input type="radio" name="store_api_mode" value="open" <?php checked($mode,'open'); ?>> Open</label><br>
									<label><input type="radio" name="store_api_mode" value="same-origin" <?php checked($mode,'same-origin'); ?>> Same-origin required (default)</label><br>
									<label><input type="radio" name="store_api_mode" value="js-cookie" <?php checked($mode,'js-cookie'); ?>> JS cookie required</label><br>
									<label><input type="radio" name="store_api_mode" value="api-key" <?php checked($mode,'api-key'); ?>> API-key required</label>
								</fieldset>
								<p class="description">
									<strong>Same-origin:</strong> blocks cross-site scrapers (checks <code>Origin/Referer</code>).<br>
									<strong>JS cookie:</strong> ensures a real browser (uses your JS challenge cookie).<br>
									<strong>API-key:</strong> require <code>X-WC-API-Key</code> even for GET reads (most strict).
								</p>
							</td>
						</tr>
						<tr>
							<th>GET rate limit</th>
							<td>
								<input type="number" name="store_api_rate_limit" value="<?php echo esc_attr(get_option(SWFO_Opt::k('store_api_rate_limit'),120)); ?>" min="10" step="10">
								<p class="description">Per-IP caps for Store API GETs within the window.</p>
							</td>
						</tr>
					</table>
				</div>

				<?php submit_button('Save Settings','primary','swfo_save'); ?>
			</form>

			<!-- RECENT EVENTS -->
			<div id="swfo-panel-events" class="swfo-tab-panel">
				<h2 class="title">Recent Events</h2>					
				<?php
				// --- Filters (GET): events_q (search), events_type (type), events_p (page)
				$ev_q    = isset($_GET['events_q']) ? sanitize_text_field( wp_unslash( $_GET['events_q'] ) ) : '';
				$ev_type = isset($_GET['events_type']) ? sanitize_text_field( wp_unslash( $_GET['events_type'] ) ) : '';
				$ev_p    = isset($_GET['events_p']) ? max( 1, intval( wp_unslash( $_GET['events_p'] ) ) ) : 1;

				// unique types for dropdown
				$types = array_values(array_unique(array_map(function($r){ return $r['type'] ?? ''; }, $logs)));
				sort($types);

				// apply filters
				$logs_f = array_values(array_filter($logs, function($r) use ($ev_q,$ev_type){
					$ok = true;
					if($ev_type !== '') $ok = $ok && (isset($r['type']) && stripos($r['type'],$ev_type)!==false);
					if($ev_q !== ''){
						$hay = strtolower( ( ($r['type']??'').' '.($r['note']??'') ) );
						$ok  = $ok && (strpos($hay, strtolower($ev_q)) !== false);
					}
					return $ok;
				}));

				list($rows,$cur,$pages,$total) = $this->paginate_array($logs_f, $ev_p, 50);
				?>

				<form method="get" class="search-form" style="margin:6px 0;">
					<input type="hidden" name="page" value="swfo">
					<input type="hidden" name="swfo_tab" value="events">
					<input type="search" name="events_q" value="<?php echo esc_attr($ev_q); ?>" placeholder="Search note/type…">
					<select name="events_type">
						<option value="">All types</option>
						<?php foreach($types as $t): if($t==='') continue; ?>
							<option value="<?php echo esc_attr($t); ?>" <?php selected($ev_type,$t); ?>><?php echo esc_html($t); ?></option>
						<?php endforeach; ?>
					</select>
					<button class="button">Filter</button>
					<a class="button" href="<?php echo esc_url( $this->tab_url('events') ); ?>">Reset</a>
				</form>

				<?php $this->render_pager('events','events_p',$cur,$pages, ['events_q'=>$ev_q,'events_type'=>$ev_type]); ?>

				<?php if(empty($rows)): ?>
					<p><em>No matching events.</em></p>
				<?php else: ?>
					<table class="widefat striped">
						<thead><tr><th style="width:160px;">Time</th><th style="width:180px;">Type</th><th>Note</th></tr></thead>
						<tbody id="swfo-events-body">
						<?php foreach($rows as $l): ?>
							<tr>
								<td><?php echo esc_html(date('Y-m-d H:i:s',$l['t'])); ?></td>
								<td><?php echo esc_html($l['type']); ?></td>
								<td><?php echo esc_html($l['note']); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<?php $this->render_pager('events','events_p',$cur,$pages, ['events_q'=>$ev_q,'events_type'=>$ev_type]); ?>
				<p class="description"><?php echo intval($total); ?> event(s) total after filter.</p>
			</div>

			<!-- API HITS -->
			<div id="swfo-panel-apihits" class="swfo-tab-panel">
				<h2 class="title">API Hits (wp-json)</h2>
				<p class="description">Newest first. Logs every REST request (including WooCommerce). Sensitive fields are masked.</p>

				<div class="swfo-two-col">
					<div>
						<?php
						$export_url = wp_nonce_url( admin_url('admin-post.php?action=swfo_export_hits'), 'swfo_export_hits' );
						$clear_url  = wp_nonce_url( admin_url('admin-post.php?action=swfo_clear_hits'),  'swfo_clear_hits'  );
						?>
						<div style="margin:8px 0;">
							<a class="button button-secondary" href="<?php echo esc_url($export_url); ?>">Export CSV</a>
							<a class="button button-link-delete" href="<?php echo esc_url($clear_url); ?>"
								onclick="return confirm('Clear all API hits?');">Clear hits</a>
						</div>
					</div>
				</div>

				<?php
				$hits = $this->api_hits_get();

				// Filters: hits_q (path/data), hits_ip, hits_method, hits_p
				$h_q   = isset($_GET['hits_q']) ? sanitize_text_field( wp_unslash( $_GET['hits_q'] ) ) : '';
				$h_ip  = isset($_GET['hits_ip']) ? sanitize_text_field( wp_unslash( $_GET['hits_ip'] ) ) : '';
				$h_m   = isset($_GET['hits_m']) ? strtoupper( sanitize_text_field( wp_unslash( $_GET['hits_m'] ) ) ) : '';
				$h_p   = isset($_GET['hits_p']) ? max( 1, intval( wp_unslash( $_GET['hits_p'] ) ) ) : 1;

				$methods = array_values(array_unique(array_map(function($r){ return strtoupper($r['m']??''); }, $hits)));
				sort($methods);

				$hits_f = array_values(array_filter($hits, function($r) use ($h_q,$h_ip,$h_m){
					$ok = true;
					if($h_ip !== '') $ok = $ok && (isset($r['ip']) && stripos($r['ip'],$h_ip)!==false);
					if($h_m !== '')  $ok = $ok && (strtoupper($r['m']??'') === $h_m);
					if($h_q !== ''){
						$hay = strtolower( ($r['path']??'').' '.($r['route']??'').' '.wp_json_encode($r['data']??'') );
						$ok  = $ok && (strpos($hay, strtolower($h_q)) !== false);
					}
					return $ok;
				}));

				list($rows,$cur,$pages,$total) = $this->paginate_array($hits_f, $h_p, 50);
				?>

				<form method="get" class="search-form" style="margin:6px 0;">
					<input type="hidden" name="page" value="swfo">
					<input type="hidden" name="swfo_tab" value="apihits">
					<input type="search" name="hits_q" value="<?php echo esc_attr($h_q); ?>" placeholder="Search path/data…">
					<input type="text" name="hits_ip" value="<?php echo esc_attr($h_ip); ?>" placeholder="IP">
					<select name="hits_m">
						<option value="">Any method</option>
						<?php foreach($methods as $m): if($m==='') continue; ?>
							<option value="<?php echo esc_attr($m); ?>" <?php selected($h_m,$m); ?>><?php echo esc_html($m); ?></option>
						<?php endforeach; ?>
					</select>
					<button class="button">Filter</button>
					<a class="button" href="<?php echo esc_url( $this->tab_url('apihits') ); ?>">Reset</a>
				</form>

				<?php $this->render_pager('apihits','hits_p',$cur,$pages, ['hits_q'=>$h_q,'hits_ip'=>$h_ip,'hits_m'=>$h_m]); ?>

				<?php if(empty($rows)): ?>
					<p><em>No matching hits.</em></p>
				<?php else: ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th style="width:160px;">Date/Time</th>
								<th style="width:110px;">IP</th>
								<th style="width:80px;">Method</th>
								<th>Path</th>
								<th>Data (masked)</th>
							</tr>
						</thead>
						<tbody id="swfo-hits-body">
							<?php foreach($rows as $h): 
								$dt = isset($h['t']) ? date('Y-m-d H:i:s', (int)$h['t']) : '';
								$ip = esc_html($h['ip'] ?? '');
								$m  = esc_html(strtoupper($h['m'] ?? ''));
								$p  = esc_html($h['path'] ?? ($h['route'] ?? ''));
								$d  = is_array($h['data']) ? wp_json_encode($h['data']) : (string)($h['data'] ?? '');
							?>
							<tr>
								<td><?php echo esc_html($dt); ?></td>
								<td><code><?php echo $ip; ?></code></td>
								<td><?php echo $m; ?></td>
								<td><code><?php echo $p; ?></code></td>
								<td><code style="white-space:pre-wrap;word-break:break-word;display:block;max-height:6.5em;overflow:auto;"><?php echo esc_html(mb_substr($d,0,3000)); ?></code></td>
							</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<?php $this->render_pager('apihits','hits_p',$cur,$pages, ['hits_q'=>$h_q,'hits_ip'=>$h_ip,'hits_m'=>$h_m]); ?>
				<p class="description"><?php echo intval($total); ?> hit(s) total after filter.</p>

			</div>

			<script>
			(function(){
				function sel(q){return document.querySelector(q)}
				function all(q){return Array.prototype.slice.call(document.querySelectorAll(q))}
				function activate(tab){
					all('.nav-tab').forEach(a=>a.classList.remove('nav-tab-active'));
					var nav = sel('.nav-tab[data-tab="'+tab+'"]'); if(nav) nav.classList.add('nav-tab-active');
					all('.swfo-tab-panel').forEach(p=>p.classList.remove('is-active'));
					var panel = sel('#swfo-panel-' + tab); if(panel) panel.classList.add('is-active');
					var hidden = sel('#swfo_tab'); if(hidden) hidden.value = tab; // <-- keep form in sync
				}
				var params = new URLSearchParams(location.search);
				var tab = params.get('swfo_tab') || (location.hash||'#status').replace('#','');
				if(!document.getElementById('swfo-panel-'+tab)) tab='status';
				activate(tab);
				all('.nav-tab').forEach(a=>{
					a.addEventListener('click', function(e){
						e.preventDefault();
						var t = this.getAttribute('data-tab');
						var url = new URL(location.href);
						url.searchParams.set('swfo_tab', t);
						url.hash = t;
						history.replaceState(null,'',url.toString());
						activate(t);
					});
				});
			})();
			</script>
		</div>
		<?php
	}

	/**
	 * Persist plugin settings from the admin form submission.
	 *
	 * Verifies and sanitizes incoming `$_POST` values, then updates the
	 * corresponding options namespaced with {@see SWFO_Opt::k()}. Numeric fields
	 * are cast to integers; other scalar fields are sanitized with
	 * {@see sanitize_text_field()}, and the webhook URL is sanitized with
	 * {@see esc_url_raw()}.
	 *
	 * Booleans are stored based on the presence of their checkbox fields:
	 * - enable_js_challenge
	 * - enable_honeypot
	 * - enable_hmac
	 * - use_redis
	 * - log_to_error_log
	 * - captcha_enabled
	 * - enable_api_hit_logging
	 *
	 * Special handling:
	 * - `api_hits_max` is clamped to a minimum of 100.
	 * - `store_api_rate_limit` is clamped to a minimum of 10.
	 * - `store_api_mode` must be one of: `open`, `same-origin`, `js-cookie`, `api-key`.
	 * - `allowlist_cidrs`, `ua_denylist`, and `soft_deny_cidrs` are parsed from
	 *   newline-delimited text into trimmed arrays (empty lines removed).
	 * - Redis credentials respect constants when defined:
	 *     - `SWFO_REDIS_AUTH`: if defined, the option is not changed; otherwise,
	 *       the posted `redis_auth` is saved unless it equals the mask `********`.
	 *     - `SWFO_REDIS_DB`: if defined, the option is not changed; otherwise,
	 *       the posted `redis_db` is saved with a minimum of 0.
	 *
	 * This method does not perform nonce or capability checks; callers (e.g.
	 * {@see self::admin_page()}) are responsible for verifying the request
	 * authenticity and user capabilities before invoking it.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function save_settings(){
		$fields = [
			'window_seconds','ip_rate_limit','email_rate_limit','required_cookie','hmac_secret','redis_host','redis_port','logs_max','webhook_url','captcha_after_soft_blocks'
		];
		foreach($fields as $f){
			if( isset( $_POST[$f] ) ) update_option( SWFO_Opt::k($f), is_numeric( wp_unslash( $_POST[$f] ) ) ? intval( wp_unslash( $_POST[$f] ) ) : sanitize_text_field( wp_unslash( $_POST[$f] ) ) );
		}
		update_option(SWFO_Opt::k('enable_js_challenge'), isset($_POST['enable_js_challenge']));
		update_option(SWFO_Opt::k('enable_honeypot'), isset($_POST['enable_honeypot']));
		update_option(SWFO_Opt::k('enable_hmac'), isset($_POST['enable_hmac']));
		update_option(SWFO_Opt::k('use_redis'), isset($_POST['use_redis']));
		update_option(SWFO_Opt::k('log_to_error_log'), isset($_POST['log_to_error_log']));
		update_option(SWFO_Opt::k('captcha_enabled'), isset($_POST['captcha_enabled']));
		
		if(isset($_POST['api_hits_max'])) update_option(SWFO_Opt::k('api_hits_max'), max(100, intval($_POST['api_hits_max'])));
		update_option(SWFO_Opt::k('enable_api_hit_logging'), isset($_POST['enable_api_hit_logging']));

		// Redis auth/db (respect constants if defined)
		if ( ! defined('SWFO_REDIS_AUTH') && isset($_POST['redis_auth']) ) {
			$val = sanitize_text_field( wp_unslash( $_POST['redis_auth'] ) );
			// Treat ******** as mask ONLY if that exact value was shown by us
			$masked = '********';
			if ( $val !== $masked ) {
				update_option( SWFO_Opt::k('redis_auth'), $val );
			}
		}
		if ( ! defined('SWFO_REDIS_DB') && isset($_POST['redis_db']) ) {
			update_option( SWFO_Opt::k('redis_db'), max(0, (int) $_POST['redis_db']) );
		}

		if(isset($_POST['store_api_rate_limit'])) update_option(SWFO_Opt::k('store_api_rate_limit'), max(10, intval($_POST['store_api_rate_limit'])));
		if(isset($_POST['store_api_mode'])){
			$m = sanitize_text_field( wp_unslash( $_POST['store_api_mode'] ) );
			if(in_array($m, ['open','same-origin','js-cookie','api-key'], true)){
				update_option(SWFO_Opt::k('store_api_mode'), $m);
			}
		}

		foreach(['allowlist_cidrs','ua_denylist','soft_deny_cidrs'] as $arr){
			$lines = isset($_POST[$arr]) ? array_filter(array_map('trim', explode("\n", $_POST[$arr]))) : [];
			update_option(SWFO_Opt::k($arr), $lines);
		}

		if (isset($_POST['webhook_url'])) {
			update_option(SWFO_Opt::k('webhook_url'), esc_url_raw($_POST['webhook_url']));
		}
	}

	/**
	 * Generate and store a new API key, then redirect back to the settings page.
	 *
	 * Capability: requires the current user to have the `manage_options` capability.
	 * A 48-character hex token is generated using {@see random_bytes()}, stored
	 * only briefly in a transient (`swfo_last_key`) so it can be shown once in the
	 * UI, while a bcrypt hash of the key is persisted in the `api_keys` option
	 * (namespaced via {@see SWFO_Opt::k()}).
	 *
	 * Side effects:
	 * - Updates the `swfo_api_keys` option with a new entry keyed by a time-based ID.
	 * - Sets a transient `swfo_last_key` (TTL ~20s) containing the plaintext key for
	 *   one-time display in the admin screen.
	 * - Performs a safe redirect back to the plugin admin page and terminates execution.
	 *
	 * Security notes:
	 * - Plaintext keys are never stored in the database; only their hashes are.
	 * - The transient holds the plaintext key briefly for display and then expires.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function handle_generate_key(){
		if(!current_user_can('manage_options')) wp_die('Forbidden');
		$key = bin2hex(random_bytes(24));
		$kid = 'key_'.time();
		$keys = get_option(SWFO_Opt::k('api_keys'),[]);
		$keys[$kid]=password_hash($key, PASSWORD_DEFAULT);
		update_option(SWFO_Opt::k('api_keys'),$keys);
		set_transient('swfo_last_key',$key,20);
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}

	/**
	 * Delete a stored API key by ID and redirect back to the settings screen.
	 *
	 * Requires the current user to have the `manage_options` capability and a valid
	 * nonce (`swfo_del_key`) passed via the `_wpnonce` query arg. The key identifier
	 * is read from the `id` query arg, sanitized, and—if present in the stored
	 * `api_keys` option (namespaced via {@see SWFO_Opt::k()})—removed before the
	 * option is updated.
	 *
	 * Side effects:
	 * - Updates the `swfo_api_keys` option to remove the specified key.
	 * - Performs a redirect to the plugin admin page and exits.
	 *
	 * Security:
	 * - Verifies capability and nonce before mutating options.
	 * - Sanitizes all incoming query parameters.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function handle_delete_key(){
		if(!current_user_can('manage_options') || !wp_verify_nonce($_GET['_wpnonce']??'','swfo_del_key')) wp_die('Forbidden');
		$id=sanitize_text_field(wp_unslash($_GET['id']??''));
		$keys = get_option(SWFO_Opt::k('api_keys'),[]);
		if(isset($keys[$id])){ unset($keys[$id]); update_option(SWFO_Opt::k('api_keys'),$keys); }
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}

	/**
	 * Create (or overwrite) a named bypass token and redirect to the settings page.
	 *
	 * Expects a valid nonce for the action `swfo_add_bypass` and the current user to
	 * have the `manage_options` capability. The bypass entry is stored in the
	 * `bypass_tokens` option (namespaced via {@see SWFO_Opt::k()}).
	 *
	 * Input (POST):
	 * - `bp_name`  (string) Human-readable identifier for the token. Sanitized via
	 *               `sanitize_text_field()`. Defaults to `bp_{timestamp}` when empty.
	 * - `bp_token` (string) Raw token to store. Trimmed; if omitted or empty, a
	 *               random 32-hex-char token is generated (`random_bytes(16)`).
	 *
	 * Behavior:
	 * - Loads the current bypass token map, inserts/overwrites the `[name] => token`
	 *   pair, and updates the option.
	 * - Redirects back to the plugin admin page and terminates execution.
	 *
	 * Security:
	 * - Verifies capability and nonce before mutating options.
	 * - Sanitizes all user-supplied fields.
	 * - Token generation uses cryptographically secure randomness.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function handle_add_bypass(){
		if ( ! current_user_can('manage_options') || ! check_admin_referer('swfo_add_bypass') ) wp_die('Forbidden');
		$name = sanitize_text_field(wp_unslash($_POST['bp_name']??'bp_'.time()));
		$tok  = trim($_POST['bp_token']??'');
		if($tok==='') $tok = bin2hex(random_bytes(16));
		$bp = get_option(SWFO_Opt::k('bypass_tokens'),[]);
		$bp[$name]=$tok;
		update_option(SWFO_Opt::k('bypass_tokens'),$bp);
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}

	/**
	 * Delete a named bypass token and redirect back to the settings screen.
	 *
	 * Requires the current user to have the `manage_options` capability and a valid
	 * nonce for the action `swfo_del_bp`. If the provided name exists in the
	 * `bypass_tokens` option (namespaced via {@see SWFO_Opt::k()}), the entry is
	 * removed and the option is updated.
	 *
	 * Input (GET):
	 * - `_wpnonce` (string) Security nonce for `swfo_del_bp`. Verified via
	 *   `wp_verify_nonce()`.
	 * - `name`     (string) The bypass token key to remove. Sanitized with
	 *   `sanitize_text_field()`.
	 *
	 * Behavior:
	 * - Validates capability and nonce.
	 * - Loads the bypass token map; if the key exists, unsets it and updates the option.
	 * - Redirects to the plugin admin page (`admin.php?page=swfo`) and terminates execution.
	 *
	 * Security:
	 * - Capability check prevents unauthorized access.
	 * - Nonce verification protects against CSRF.
	 * - User-provided input is sanitized before use.
	 *
	 * @since 1.0.0
	 * @return void
	 */	
	function handle_delete_bypass(){
		if(!current_user_can('manage_options') || !wp_verify_nonce($_GET['_wpnonce']??'','swfo_del_bp')) wp_die('Forbidden');
		$name=sanitize_text_field(wp_unslash($_GET['name']??''));
		$bp = get_option(SWFO_Opt::k('bypass_tokens'),[]);
		if(isset($bp[$name])){ unset($bp[$name]); update_option(SWFO_Opt::k('bypass_tokens'),$bp); }
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}

	/**
	 * Retrieve the current site's host (lowercased) for same-origin checks.
	 *
	 * Uses {@see home_url()} to obtain the site's URL and parses it with
	 * {@see parse_url()} to extract the `host` component. The returned value is
	 * normalized to lowercase. If the host cannot be determined, an empty string
	 * is returned.
	 *
	 * Note: The scheme and port are not included—only the hostname/FQDN.
	 *
	 * @since 1.0.0
	 *
	 * @return string The site host in lowercase, or an empty string if unavailable.
	 */
	private function site_host(){
		$u = home_url('/');
		$p = parse_url($u);
		return isset($p['host']) ? strtolower($p['host']) : '';
	}

	/**
	 * Determine whether the incoming request is same-origin as the site.
	 *
	 * This method compares the hostname from the incoming request's
	 * `Origin` (preferred) or `Referer` header with the site's host
	 * (as returned by {@see self::site_host()}).
	 *
	 * Behavior:
	 * - If the site host cannot be determined, returns false.
	 * - If neither `Origin` nor `Referer` is present, returns false.
	 * - Parses the header URL and compares the lowercased host components.
	 *
	 * Security notes:
	 * - Only the hostname is compared; scheme and port are ignored.
	 * - Malformed header values are handled defensively and treated as non-matching.
	 *
	 * @since 1.0.0
	 *
	 * @param WP_REST_Request $request The current REST request (not used directly; present for signature parity).
	 * @return bool True if the request appears to be same-origin, false otherwise.
	 */
	private function is_same_origin($request){
		$site = $this->site_host();
		if(!$site) return false;
		$hdr = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
		if(!$hdr) return false;  // block when no Origin/Referer is sent
		$p = parse_url($hdr);
		$h = isset($p['host']) ? strtolower($p['host']) : '';
		return $h === $site;
	}

	/**
	 * REST abuse gate and WooCommerce route hardening.
	 *
	 * Runs early in the REST request lifecycle (via the
	 * `rest_request_before_callbacks` filter) to enforce multiple layers of
	 * protection specifically for WooCommerce REST and Store API routes:
	 *
	 * - Hard bans: immediate 403 for banned IPs.
	 * - Per-route exemptions via `swfo_route_is_exempt` filter.
	 * - Store API modes: same-origin, JS-cookie, or API-key (with optional HMAC).
	 * - Store API rate limits: GET and optional write limits for cart/checkout.
	 * - Header bypass for trusted S2S jobs (`X-SWFO-Bypass`).
	 * - CIDR allowlist (full bypass) and soft-deny (429) networks.
	 * - UA denylist and basic Origin/Referer sanity checks.
	 * - Optional API key + HMAC verification for S2S integrations.
	 * - Sliding-window IP rate limit for WooCommerce REST traffic.
	 * - Checkout/order POST protections: honeypot, JS cookie, email rate limit,
	 *   and optional math CAPTCHA.
	 *
	 * This callback MUST return the original result when the request is allowed,
	 * or a `WP_Error` to short-circuit with an appropriate status code.
	 *
	 * @since 1.0.0
	 * @since 2.1.0 Added hard IP ban enforcement, Store API write-rate limiting,
	 *              and refined Store API gating modes.
	 *
	 * @hook rest_request_before_callbacks
	 *
	 * @param WP_REST_Response|WP_Error|null $result  Preemptive response, if any, from earlier filters.
	 * @param array                          $handler Route handler details (unused here but required by the filter signature).
	 * @param WP_REST_Request                $request The current REST request.
	 * @return WP_REST_Response|WP_Error|null Unchanged result to continue processing, or a WP_Error to block the request.
	 */
	public function rest_gate( $result, $handler, $request ) {
		// Ensure we actually got a WP_REST_Request
		if ( ! ( $request instanceof WP_REST_Request ) ) {
			return $result;
		}

		$route = $request->get_route();
		$ip    = $this->client_ip();

		// Hard ban checks (IP/email)
		if ( $this->is_banned_ip($ip) ) {
			$this->log('hard_ban_ip_hit', 'ip:'.$ip.' route:'.$route);
			return new WP_Error('swfo_banned', 'Forbidden', ['status'=>403]);
		}

		// Per-route exemptions for trusted integrations.
		if ( apply_filters( 'swfo_route_is_exempt', false, $route, $request ) ) {
			return $result;
		}

		// Target Woo routes specifically (v2/v3, analytics, store API, legacy wc-api).
		$wc_target = (
			strpos( $route, '/wc/' ) !== false ||
			strpos( $route, '/wc-' ) !== false ||            // e.g. wc-analytics
			strpos( $route, '/wc/store/' ) !== false ||      // Store API
			strpos( $route, '/wc-api/' ) !== false
		);
		if ( ! $wc_target ) {
			return $result;
		}

		// Allow Woo Admin (analytics) + any trusted admin REST calls
		if ( $this->is_trusted_admin_request( $request ) ) {
			return $result;
		}
		// Explicitly exempt Woo Analytics (browser, nonce-authenticated)
		if ( strpos( $route, '/wc-analytics/' ) !== false ) {
			return $result;
		}

		/* ----------------------- Store API protections ----------------------- */
		$is_store = ( strpos( $route, '/wc/store/' ) !== false );
		if ( $is_store ) {
			$mode    = get_option( SWFO_Opt::k('store_api_mode'), 'same-origin' );
			$method  = $request->get_method();
			// Treat cart/checkout as sensitive: apply to ALL methods.
			$is_cart = (strpos($route, '/wc/store/cart/') !== false) || (strpos($route, '/wc/store/checkout') !== false);

			if ( $mode === 'same-origin' ) {
				if ( ! $this->is_same_origin( $request ) ) {
					$this->log('storeapi_same_origin_block', 'ip:'.$ip.' route:'.$route);
					return new WP_Error('swfo_store_same_origin','Same-origin required',['status'=>403]);
				}
			} elseif ( $mode === 'js-cookie' ) {
				$c = get_option( SWFO_Opt::k('required_cookie'), 'swfo_js' );
				if ( empty($_COOKIE[$c]) ) {
					$this->log('storeapi_cookie_block','ip:'.$ip.' route:'.$route);
					return new WP_Error('swfo_store_cookie','JS verification required',['status'=>403]);
				}
			} elseif ( $mode === 'api-key' ) {
				$key = $request->get_header('x-wc-api-key');
				if ( ! $key || ! $this->api_ok($key) ) {
					$this->log('storeapi_key_block','ip:'.$ip.' route:'.$route);
					return new WP_Error('swfo_store_key','API key required',['status'=>401]);
				}
				// Optional HMAC for reads/writes when API-key mode is on
				if ( get_option(SWFO_Opt::k('enable_hmac'), false) ) {
					$h  = $request->get_header( 'x-wc-hmac' );
					$ts = $request->get_header( 'x-wc-timestamp' );
					if ( ! $this->hmac_ok( $request, $h, $ts ) ) {
						$this->touch_fail('hmac',$ip);
						return new WP_Error('swfo_bad_sig','Bad signature',['status'=>403]);
					}
				}
			}

			// GET rate limit for Store API (unchanged)
			if ( $method === 'GET' ) {
				$win         = (int) get_option( SWFO_Opt::k('window_seconds'), 60 );
				$store_limit = (int) get_option( SWFO_Opt::k('store_api_rate_limit'), 120 );
				$rcnt = $this->incr('store_get_ip:'.$ip, $win + rand(0,3));
				if ( $rcnt > $store_limit ) {
					$this->log('rate_store_get', "ip=$ip cnt=$rcnt route=$route");
					return new WP_Error('swfo_store_rl','Too many requests',['status'=>429]);
				}
			}

			// OPTIONAL: write rate limit for cart/checkout POST/PUT/DELETE
			if ( $is_cart && $method !== 'GET' ) {
				$win = (int) get_option( SWFO_Opt::k('window_seconds'), 60 );
				$lim = max(20, (int) get_option( SWFO_Opt::k('store_api_write_rate_limit'), 60 ));
				$rc  = $this->incr('store_write_ip:'.$ip, $win + rand(0,3));
				if ( $rc > $lim ) {
					$this->log('rate_store_write', "ip=$ip cnt=$rc route=$route");
					return new WP_Error('swfo_store_write_rl','Too many requests',['status'=>429]);
				}
			}
		}
		/* -------------------------------------------------------------------- */

		// Header-based bypass for server-to-server jobs.
		$bypass = $request->get_header( 'x-swfo-bypass' );
		if ( $bypass && $this->bypass_ok( $bypass ) ) {
			return $result;
		}

		// CIDR allowlist (full bypass).
		foreach ( (array) get_option( SWFO_Opt::k( 'allowlist_cidrs' ), [] ) as $cidr ) {
			if ( $this->ip_in_cidr( $ip, $cidr ) ) {
				return $result;
			}
		}

		// Soft-deny CIDR (429).
		foreach ( (array) get_option( SWFO_Opt::k( 'soft_deny_cidrs' ), [] ) as $cidr ) {
			if ( $this->ip_in_cidr( $ip, $cidr ) ) {
				$this->log( 'soft_deny', 'ip:' . $ip . ' route:' . $route );
				return new WP_Error( 'swfo_soft_deny', 'Too many requests', [ 'status' => 429 ] );
			}
		}

		// UA denylist + minimal Origin/Referer sanity.
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
		foreach ( (array) get_option( SWFO_Opt::k( 'ua_denylist' ), [] ) as $deny ) {
			if ( stripos( $ua, $deny ) !== false ) {
				$this->touch_fail( 'ua', $ip );
				return new WP_Error( 'swfo_forbidden', 'Forbidden', [ 'status' => 403 ] );
			}
		}
		$origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
		if ( $origin && preg_match( '/(javascript:|data:)/i', $origin ) ) {
			$this->log( 'bad_origin', $origin );
			return new WP_Error( 'swfo_forbidden', 'Forbidden', [ 'status' => 403 ] );
		}

		// API-key header gate (optional per your use).
		if ( $key = $request->get_header( 'x-wc-api-key' ) ) {
			if ( ! $this->api_ok( $key ) ) {
				$this->touch_fail( 'api', $ip );
				return new WP_Error( 'swfo_bad_key', 'Invalid API key', [ 'status' => 401 ] );
			}
		}

		// Optional HMAC (only when API key is present -> S2S integrations)
		if ( get_option( SWFO_Opt::k( 'enable_hmac' ), false ) && $request->get_header( 'x-wc-api-key' ) ) {
			$h  = $request->get_header( 'x-wc-hmac' );
			$ts = $request->get_header( 'x-wc-timestamp' );
			if ( ! $this->hmac_ok( $request, $h, $ts ) ) {
				$this->touch_fail( 'hmac', $ip );
				return new WP_Error( 'swfo_bad_sig', 'Bad signature', [ 'status' => 403 ] );
			}
		}

		// Sliding window IP rate limit (+ small jitter).
		$win   = (int) get_option( SWFO_Opt::k( 'window_seconds' ), 60 );
		$count = $this->incr( 'ip:' . $ip, $win + rand( 0, 3 ) );
		if ( $count > (int) get_option( SWFO_Opt::k( 'ip_rate_limit' ), 50 ) ) {
			$this->log( 'rate_ip', "ip=$ip count=$count" );
			return new WP_Error( 'swfo_rl', 'Too many requests', [ 'status' => 429 ] );
		}

		// Checkout/order creation protections (REST).
		if ( preg_match( '#/orders#', $route ) && $request->get_method() === 'POST' ) {

			// Honeypot.
			if ( get_option( SWFO_Opt::k( 'enable_honeypot' ), true ) ) {
				$hp = $request->get_param( 'swfo_hp' );
			if ( ! is_null( $hp ) && $hp !== '' ) {
					$this->log( 'hp_rest', 'ip:' . $ip );
					return new WP_Error( 'swfo_hp', 'Forbidden', [ 'status' => 403 ] );
				}
			}

			// JS cookie challenge.
			if ( get_option( SWFO_Opt::k( 'enable_js_challenge' ), true ) ) {
				$c = get_option( SWFO_Opt::k( 'required_cookie' ), 'swfo_js' );
				if ( empty( $_COOKIE[ $c ] ) ) {
					$this->log( 'cookie_missing', 'ip:' . $ip );
					return new WP_Error( 'swfo_js', 'JS verification required', [ 'status' => 403 ] );
				}
			}

			// Safe email extraction (avoid "offset on null" notices).
			$billing = (array) $request->get_param( 'billing' );
			$email   = $billing['email']
				?? $request->get_param( 'billing_email' )
				?? $request->get_param( 'email' )
				?? '';

			$email = is_string( $email ) ? strtolower( trim( $email ) ) : '';

			// Email rate limit.
			if ( $email !== '' ) {
				$ecount = $this->incr( 'email:' . $email, $win + rand( 0, 3 ) );
				if ( $ecount > (int) get_option( SWFO_Opt::k( 'email_rate_limit' ), 10 ) ) {
					$this->log( 'rate_email', "email=$email ip=$ip c=$ecount" );
					return new WP_Error( 'swfo_rl_email', 'Too many attempts', [ 'status' => 429 ] );
				}

				// Enforce math CAPTCHA when enabled (align with checkout form)
				if ( get_option( SWFO_Opt::k( 'captcha_enabled' ), true ) ) {
					$ans = $request->get_param( 'swfo_captcha' );
					$op  = $request->get_param( 'swfo_captcha_op' );
					if ( ! $this->captcha_verify( $ans, $request->get_param( 'swfo_captcha_nonce' ), $op ) ) {
						return new WP_Error( 'swfo_need_captcha', 'Captcha required', [ 'status' => 403 ] );
					}
				}
			}
		}

		return $result;
	}

	/**
	 * Build a normalized ban bucket key for Redis/transient storage.
	 *
	 * Normalizes the provided value by lowercasing and trimming it, then hashes it
	 * (MD5) to form a compact, uniform key under the "ban:{type}:" namespace.
	 * Useful for IP/email (or other identifier) hard-ban lookups.
	 *
	 * Example result: "ban:ip:7c4ff521986b4ff8d29440beec01972d"
	 *
	 * @since 2.1.0
	 *
	 * @param string $type Ban category (e.g. 'ip', 'email', 'ua').
	 * @param string $val  Raw identifier value to normalize and hash.
	 * @return string      Storage key string for this ban bucket.
	 */
	private function ban_key($type, $val){ return "ban:{$type}:".md5(strtolower(trim($val))); }

	/**
	 * Hard-ban an IP for a fixed TTL using Redis or transients.
	 *
	 * Stores a ban flag under a normalized bucket key (via {@see self::ban_key()}):
	 * - If Redis is available/enabled, uses SETEX on "swfo:{key}".
	 * - Otherwise falls back to a WordPress transient "swfo_{key}".
	 *
	 * Also emits an operational log entry "ban_ip_set" with the IP and TTL.
	 *
	 * @since 2.1.0
	 *
	 * @param string $ip          The client IP address to ban.
	 * @param int    $ttl_seconds Time-to-live in seconds for the ban (default 3600s).
	 * @return void
	 */
	public function ban_ip($ip, $ttl_seconds = 3600){
		$key = $this->ban_key('ip',$ip);
		if ($this->use_redis && $this->redis){
			$this->redis->setEx('swfo:'.$key, $ttl_seconds, 1);
		} else {
			set_transient('swfo_'.$key, 1, $ttl_seconds);
		}
		$this->log('ban_ip_set', "ip=$ip ttl=$ttl_seconds");
	}

	/**
	 * Check if an IP address is currently hard-banned.
	 *
	 * Uses the normalized ban bucket key produced by {@see self::ban_key()}:
	 * - If Redis is enabled and connected, checks existence of "swfo:{key}".
	 * - Otherwise, checks the WordPress transient "swfo_{key}".
	 *
	 * @since 2.1.0
	 *
	 * @param string $ip The client IP address to test.
	 * @return bool True if the IP is banned; false otherwise.
	 */
	public function is_banned_ip($ip){
		$key = $this->ban_key('ip',$ip);
		if ($this->use_redis && $this->redis){
			return (bool) $this->redis->exists('swfo:'.$key);
		}
		return (bool) get_transient('swfo_'.$key);
	}

	/**
	 * Hard-ban an email address for a fixed duration.
	 *
	 * Generates a normalized ban bucket key via {@see self::ban_key()} and stores a
	 * marker value for the specified TTL:
	 * - If Redis is enabled and available, uses SETEX on "swfo:{key}".
	 * - Otherwise, falls back to a WordPress transient "swfo_{key}".
	 *
	 * A corresponding event is logged with type "ban_email_set".
	 *
	 * @since 2.1.0
	 *
	 * @param string $email        The email address to ban (will be normalized).
	 * @param int    $ttl_seconds  Time-to-live in seconds for the ban. Default 3600.
	 * @return void
	 */
	public function ban_email($email, $ttl_seconds = 3600){
		$key = $this->ban_key('email',$email);
		if ($this->use_redis && $this->redis){
			$this->redis->setEx('swfo:'.$key, $ttl_seconds, 1);
		} else {
			set_transient('swfo_'.$key, 1, $ttl_seconds);
		}
		$this->log('ban_email_set', "email=$email ttl=$ttl_seconds");
	}

	/**
	 * Check if an email address is currently hard-banned.
	 *
	 * Resolves a normalized ban bucket key via {@see self::ban_key()} and tests for
	 * the presence of the ban marker:
	 * - When Redis is enabled and available, checks existence of "swfo:{key}".
	 * - Otherwise, checks the WordPress transient "swfo_{key}".
	 *
	 * @since 2.1.0
	 *
	 * @param string $email Email address to test (will be normalized).
	 * @return bool True if the email is banned; false otherwise.
	 */
	public function is_banned_email($email){
		$key = $this->ban_key('email',$email);
		if ($this->use_redis && $this->redis){
			return (bool) $this->redis->exists('swfo:'.$key);
		}
		return (bool) get_transient('swfo_'.$key);
	}

	/**
	 * Output checkout form hardening fields (honeypot and math CAPTCHA).
	 *
	 * When enabled via plugin options, prints:
	 * - A hidden honeypot input (`swfo_hp`) used to trap naive bots.
	 * - A lightweight, stateless math CAPTCHA (operands, operator, and a nonce)
	 *   that is later verified server-side.
	 *
	 * Escapes dynamic values and avoids introducing additional scripts/styles;
	 * intended for use inside WooCommerce checkout form markup.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function checkout_fields(){
		if(get_option(SWFO_Opt::k('enable_honeypot'),true)){
			echo '<p style="display:none"><label>Leave empty<input type="text" name="swfo_hp" value=""></label></p>';
		}
		if(get_option(SWFO_Opt::k('captcha_enabled'), true)){
			$q = $this->captcha_issue(); // now returns op too
			$opLabel = ['+'=>'+','-'=>'−','*'=>'×'][$q['op']] ?? $q['op'];
			echo '<p id="swfo-captcha-wrap"><label>Anti-bot check: '.
				'<span id="swfo-cap-a">'.intval($q['a']).'</span> '.
				'<span id="swfo-cap-op">'.$opLabel.'</span> '.
				'<span id="swfo-cap-b">'.intval($q['b']).'</span> = '.
				'<input type="text" name="swfo_captcha" id="swfo_captcha" value="" autocomplete="off" style="width:80px"></label>'.
				'<input type="hidden" name="swfo_captcha_nonce" value="'.esc_attr($q['n']).'">'.
				'<input type="hidden" name="swfo_captcha_op" value="'.esc_attr($q['op']).'">'.
				'</p>';
		}
	}

	/**
	 * Enqueue inline JavaScript for checkout challenges.
	 *
	 * - Injects the JS cookie challenge script to set the verification cookie when
	 *   the checkout page is viewed (if enabled).
	 * - Adds an inline validator for the math CAPTCHA that prevents form submission
	 *   when the client-side answer does not match the expected result.
	 *
	 * Scripts are added as inline code to `jquery-core` to keep the plugin single-file.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function enqueue_js(){
		wp_localize_script( 'jquery-core', 'SWFOi18n', array(
    	'captchaPrompt' => __( 'Please solve the anti-bot check correctly.', 'stop-woocommerce-fake-orders' ),
    	'jsRequired'    => __( 'Please enable JavaScript to continue.', 'stop-woocommerce-fake-orders' ),
		) );

		if(is_checkout() && get_option(SWFO_Opt::k('enable_js_challenge'),true)){
			wp_add_inline_script('jquery-core', $this->js_challenge());
		}
		if ( is_checkout() && get_option(SWFO_Opt::k('captcha_enabled'), true) ){
			wp_add_inline_script('jquery-core', "
				(function(){
					function calc(a,b,op){
						a=Number(a); b=Number(b);
						if(op==='-') return a-b;
						if(op==='*') return a*b;
						return a+b;
					}
					jQuery(function($){
						var form = $('form.checkout');
						form.on('checkout_place_order', function(){
							var a = $('#swfo-cap-a').text(), b = $('#swfo-cap-b').text(), op = $('input[name=swfo_captcha_op]').val() || '+';
							var exp = calc(a,b,op);
							var ans = Number($('#swfo_captcha').val());
							if( String(ans) === '' || ans !== exp ){
								alert('Please solve the anti-bot check correctly.');
								return false;
							}
						});
					});
				})();");
		}
	}

	/**
	 * Validate checkout submission against anti-bot checks and rate limits.
	 *
	 * Performs multiple protections:
	 * - Honeypot: blocks when the hidden field is filled.
	 * - JS cookie: requires the verification cookie to be present.
	 * - Email rate limit: throttles attempts per email within the configured window.
	 * - CAPTCHA: verifies the stateless math challenge server-side.
	 *
	 * Adds WooCommerce notices on failure and logs relevant events for observability.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	function checkout_validate(){
		$ip=$this->client_ip();
		if(get_option(SWFO_Opt::k('enable_honeypot'),true) && !empty($_POST['swfo_hp'])){
			wc_add_notice('Checkout validation failed.','error'); $this->log('hp_checkout','ip:'.$ip);
		}
		if(get_option(SWFO_Opt::k('enable_js_challenge'),true)){
			$c=get_option(SWFO_Opt::k('required_cookie'),'swfo_js'); if(empty($_COOKIE[$c])){
				wc_add_notice('Please enable JavaScript to continue.','error'); $this->log('cookie_checkout','ip:'.$ip);
			}
		}
		// Email rate limit (form)
		$email = isset($_POST['billing_email'])?sanitize_email($_POST['billing_email']):'';
		if($email){
			$win=intval(get_option(SWFO_Opt::k('window_seconds'),60));
			$ecount=$this->incr('email:'.strtolower($email), $win + rand(0,3));
			if($ecount > intval(get_option(SWFO_Opt::k('email_rate_limit'),10))){
				wc_add_notice('Too many attempts. Please try later.','error');
				$this->log('rate_email_form',"email=$email ip=$ip c=$ecount");
			}
		}
		// CAPTCHA (always enforce if enabled)
		if ( get_option(SWFO_Opt::k('captcha_enabled'), true) ){
			$ok = $this->captcha_verify($_POST['swfo_captcha'] ?? '', $_POST['swfo_captcha_nonce'] ?? '', $_POST['swfo_captcha_op'] ?? '+');
			if ( ! $ok ){
				wc_add_notice('Please solve the anti-bot check correctly.','error');
				$this->log('captcha_fail','ip:'.$ip);
			}
		}
	}

	/**
	 * Reset counters after a successful checkout using the order ID.
	 *
	 * Fetches the order object and, if found, delegates to {@see success_reset()}
	 * to clear IP/email rate-limit buckets associated with the buyer. This reduces
	 * friction for legitimate customers after payment/placement succeeds.
	 *
	 * Typically hooked to `woocommerce_thankyou`.
	 *
	 * @since 1.0.0
	 *
	 * @param int $order_id WooCommerce order ID.
	 * @return void
	 */
	function success_reset_by_order_id($order_id){
		if(!$order_id) return;
		$order = wc_get_order($order_id); if($order) $this->success_reset($order);
	}

	/**
	 * Reset counters after an order status transition using the order ID.
	 *
	 * Fetches the order object for transitions such as "processing" or "completed"
	 * and, if found, delegates to {@see success_reset()} to clear IP/email
	 * rate-limit buckets associated with the buyer.
	 *
	 * Typically hooked to `woocommerce_order_status_processing` and
	 * `woocommerce_order_status_completed`.
	 *
	 * @since 1.0.0
	 *
	 * @param int $order_id WooCommerce order ID.
	 * @return void
	 */
	function success_reset_by_order_obj($order_id){
		$order = wc_get_order($order_id); if($order) $this->success_reset($order);
	}

	/**
	 * Clear buyer-related rate-limit buckets and log the reset.
	 *
	 * Derives buyer identity (billing email and customer IP) from the order object
	 * and clears corresponding counters (e.g. `email:{email}`, `ip:{ip}`) so that
	 * legitimate customers are not throttled after a successful order event.
	 * Emits a `success_reset` log entry with masked context for observability.
	 *
	 * @since 1.0.0
	 *
	 * @param \WC_Order $order The WooCommerce order object.
	 * @return void
	 */
	private function success_reset($order){
		$email = strtolower($order->get_billing_email());
		$ip = $this->client_ip_from_order($order);
		if($email) $this->reset('email:'.$email);
		if($ip) $this->reset('ip:'.$ip);
		$this->log('success_reset','email:'.$email.' ip:'.$ip);
	}

	/**
	 * Determine whether the current REST request should be trusted as an admin request.
	 *
	 * Considers two paths:
	 * 1) A logged-in user with `manage_woocommerce` or `manage_options` capability.
	 * 2) A valid REST nonce (`X-WP-Nonce`) verified against the `wp_rest` action.
	 *
	 * When true, the plugin skips certain REST gates intended only for public traffic.
	 *
	 * @since 1.0.0
	 *
	 * @param \WP_REST_Request|mixed $request REST request object (or mixed if unavailable).
	 * @return bool True if the request is trusted/admin-originated, false otherwise.
	 */
	private function is_trusted_admin_request( $request ){
		if ( function_exists('is_user_logged_in') && is_user_logged_in() ) {
			if ( current_user_can('manage_woocommerce') || current_user_can('manage_options') ) {
				return true;
			}
		}
		$nonce = is_object($request) ? $request->get_header('x-wp-nonce') : '';
		// WordPress REST uses 'wp_rest' nonce action in admin
		if ( $nonce && wp_verify_nonce( $nonce, 'wp_rest' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Validate an API key sent by a client.
	 *
	 * Compares the provided API key against the stored set of hashed keys using
	 * `password_verify()`. Keys are stored in the `swfo_api_keys` option as
	 * an associative array of `id => password_hash(key)`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key The plaintext API key supplied by the client.
	 * @return bool True if the key matches any stored hash, false otherwise.
	 */
	private function api_ok($key){
		foreach((array)get_option(SWFO_Opt::k('api_keys'),[]) as $id=>$hash){
			if(password_verify($key,$hash)) return true;
		}
		return false;
	}

	/**
	 * Validate a bypass token for trusted server-to-server jobs.
	 *
	 * Compares the provided token against the configured bypass tokens using
	 * `hash_equals()` to mitigate timing attacks. Tokens are stored in the
	 * `swfo_bypass_tokens` option as `name => token`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $token The plaintext bypass token from the `X-SWFO-Bypass` header.
	 * @return bool True if the token matches a stored value, false otherwise.
	 */
	private function bypass_ok($token){
		foreach((array)get_option(SWFO_Opt::k('bypass_tokens'),[]) as $n=>$t){
			if(hash_equals($t,$token)) return true;
		}
		return false;
	}

	/**
	 * Verify the HMAC signature for a request.
	 *
	 * Expects headers `X-WC-HMAC` and `X-WC-Timestamp`. Rejects if the shared
	 * secret is empty, headers are missing, or the timestamp is older/newer than
	 * ±5 minutes. The signing string is:
	 *
	 *     METHOD|ROUTE|BODY|TIMESTAMP
	 *
	 * Where:
	 * - METHOD is the HTTP verb from the request (e.g., GET/POST).
	 * - ROUTE is the REST route (e.g., `/wc/v3/orders`).
	 * - BODY is the raw request body.
	 * - TIMESTAMP is the integer seconds since epoch from the header.
	 *
	 * The HMAC is computed as `hash_hmac('sha256', $string, $secret)`.
	 *
	 * @since 1.0.0
	 *
	 * @param \WP_REST_Request $req The REST request object.
	 * @param string           $h   The hex-encoded HMAC from `X-WC-HMAC`.
	 * @param string|int       $ts  The timestamp from `X-WC-Timestamp`.
	 * @return bool True if the signature is valid within the allowed skew, false otherwise.
	 */
	private function hmac_ok($req,$h,$ts){
		$sec=get_option(SWFO_Opt::k('hmac_secret'),''); if(!$sec||!$h||!$ts) return false;
		if(abs(time()-intval($ts))>300) return false;
		$raw=$req->get_method().'|'.$req->get_route().'|'.$req->get_body().'|'.$ts;
		$calc=hash_hmac('sha256',$raw,$sec);
		return hash_equals($calc,$h);
	}

	/**
	 * Increment a sliding-window counter with TTL using Redis or transients.
	 *
	 * When Redis is available, uses atomic `INCR` and sets/refreshes the key's TTL.
	 * On Redis failure (caught Throwable), falls back to a WordPress transient that
	 * stores a small payload `['t' => timestamp, 'c' => count]` and expires after
	 * `$ttl + 5` seconds to provide a slight grace period.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key Counter bucket name (without the `swfo:` prefix).
	 * @param int    $ttl Time-to-live in seconds for the counter window.
	 * @return int   The incremented counter value.
	 */
	private function incr($key,$ttl){
		if($this->use_redis && $this->redis){
			try{
				$k='swfo:'.$key;
				$v=$this->redis->incr($k);
				if($this->redis->ttl($k)<1) $this->redis->expire($k,$ttl);
				return (int)$v;
			}catch(\Throwable $e){
				error_log('SWFO Redis incr fallback: '.$e->getMessage());
				$this->use_redis=false; // fall back for this request
			}
		}
		$tk='swfo_cnt_'.md5($key); $e=get_transient($tk);
		if(!is_array($e)) $e=['t'=>time(),'c'=>0];
		if(time()-$e['t']>$ttl){ $e=['t'=>time(),'c'=>1]; } else { $e['c']++; }
		set_transient($tk,$e,$ttl+5);
		return (int)$e['c'];
	}

	/**
	 * Reset (delete) a counter key from Redis or transients.
	 *
	 * Attempts to delete the Redis key first; on failure or when Redis is not in
	 * use, deletes the corresponding transient.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key Counter bucket name (without the `swfo:` prefix).
	 * @return void
	 */
	private function reset($key){
		if($this->use_redis && $this->redis){
			try{ $this->redis->del('swfo:'.$key); return; }
			catch(\Throwable $e){ error_log('SWFO Redis reset fallback: '.$e->getMessage()); $this->use_redis=false; }
		}
		delete_transient('swfo_cnt_'.md5($key));
	}

	/**
	 * Peek (read) the current value of a counter without incrementing it.
	 *
	 * When Redis is in use, fetches the value of the key; otherwise, reads the
	 * corresponding transient and extracts the count. Returns zero if the key
	 * does not exist or on any error.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key Counter bucket name (without the `swfo:` prefix).
	 * @return int   The current counter value, or zero if not found.
	 */
	private function peek($key){
		if($this->use_redis && $this->redis){
			try{
				$v=$this->redis->get('swfo:'.$key);
				return $v?intval($v):0;
			}catch(\Throwable $e){
				error_log('SWFO Redis peek fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		$e=get_transient('swfo_cnt_'.md5($key));
		return is_array($e)?intval($e['c']):0;
	}

	/**
	 * Record a soft-block event for an IP address.
	 *
	 * Increments a longer-lived "soft:<ip>" bucket to track repeated soft failures
	 * (e.g., UA deny, missing cookie, bad HMAC). The window length is derived from
	 * the configured `window_seconds` option and multiplied by 10 to retain history
	 * longer than the main rate window. Also writes an event log entry.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Short label of the failing mechanism (e.g., 'ua', 'api', 'hmac').
	 * @param string $ip     Client IP address.
	 * @return void
	 */
	private function touch_fail($bucket,$ip){
		$win=intval(get_option(SWFO_Opt::k('window_seconds'),60));
		$c=$this->incr('soft:'.$ip,$win*10); // soft block counter lasts longer
		$this->log('soft_block',"$bucket ip=$ip c=$c");
	}

	/**
	 * Retrieve recent plugin event logs from Redis (preferred) or transients.
	 *
	 * When Redis is enabled and reachable, uses a Redis list at `swfo:logs`, where each
	 * item is a serialized associative array with at least `t` (timestamp) and `type`.
	 * Falls back to a WordPress transient keyed by {@see SWFO_Opt::k()} when Redis is
	 * unavailable. Always returns a PHP array of log rows, newest-first, or an empty
	 * array if no logs are present.
	 *
	 * @since 1.0.0
	 *
	 * @return array[] Array of log entries. Each entry is an associative array with keys:
	 *                 - 't'   (int)    Unix timestamp.
	 *                 - 'type'(string) Event type identifier.
	 *                 - 'note'(string) Optional note/metadata.
	 */
	private function logs_get(){
		if($this->use_redis && $this->redis){
			try{
				$raw=$this->redis->lRange('swfo:logs',0,-1);
				if(!is_array($raw)) $raw=[];
				$o=[];
				foreach($raw as $r){ $dec=unserialize($r); if(is_array($dec)&&isset($dec['t'],$dec['type'])) $o[]=$dec; }
				return $o;
			}catch(\Throwable $e){
				error_log('SWFO Redis logs_get fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		$l=get_transient(SWFO_Opt::k('logs'));
		return is_array($l)?$l:[];
	}
	
	/**
	 * Persist recent plugin event logs to Redis or transients.
	 *
	 * Normalizes the input to an array, trims the list to the configured maximum
	 * (option `logs_max`, minimum 10), then writes the list. Uses a Redis list
	 * `swfo:logs` when available, otherwise stores the whole array in a transient.
	 *
	 * @since 1.0.0
	 *
	 * @param array $logs Ordered list of log rows (newest first). Each row should be an
	 *                    associative array containing at least 't' (int) and 'type' (string).
	 * @return void
	 */
	private function logs_set($logs){
		$logs = is_array($logs) ? $logs : [];
		$max  = intval(get_option(SWFO_Opt::k('logs_max'),300));
		$logs = array_slice($logs,0,max(10,$max));
		if($this->use_redis && $this->redis){
			try{
				$this->redis->del('swfo:logs');
				foreach(array_reverse($logs) as $l){ $this->redis->lPush('swfo:logs', serialize($l)); }
				return;
			}catch(\Throwable $e){
				error_log('SWFO Redis logs_set fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		set_transient(SWFO_Opt::k('logs'),$logs,HOUR_IN_SECONDS);
	}

	/**
	 * Append a single event row to the logs and optionally export it.
	 *
	 * Prepends a new log entry (timestamp, type, note), persists via {@see logs_set()},
	 * and, if enabled, mirrors to the PHP error log (option `log_to_error_log`) and/or
	 * POSTs a JSON payload to the configured webhook URL (option `webhook_url`).
	 *
	 * @since 1.0.0
	 *
	 * @param string $type Short machine-readable event type (e.g., 'rate_ip', 'soft_deny').
	 * @param string $note Optional human-readable note or compact metadata.
	 * @return void
	 */
	private function log($type,$note=''){
		$l=$this->logs_get(); array_unshift($l,['t'=>time(),'type'=>$type,'note'=>$note]); $this->logs_set($l);
		if(get_option(SWFO_Opt::k('log_to_error_log'),false)) error_log("[SWFO] $type - $note");
		if($u=get_option(SWFO_Opt::k('webhook_url'),'')) $this->post_webhook($u, ['t'=>time(),'type'=>$type,'note'=>$note]);
	}

	/**
	 * POST a JSON payload to a webhook URL (non-blocking).
	 * 
	 * @since 1.0.0
	 * @param string $url     The webhook URL.
	 * @param array  $payload Associative array to JSON-encode and send.
	 * @return void
	 */
	private function post_webhook($url,$payload){ wp_remote_post($url,['timeout'=>2,'blocking'=>false,'headers'=>['Content-Type'=>'application/json'],'body'=>wp_json_encode($payload)]); }

	/**
	 * Get the client's IP address, accounting for proxies.
	 * 
	 * @since 1.0.0
	 * @return string The client's IP address.
	 */
	private function client_ip(){
		if(!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP']; // CF
		if(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){ $p=explode(',',$_SERVER['HTTP_X_FORWARDED_FOR']); return trim($p[0]); }
		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}

	/**
	 * Get the client's IP address from a WooCommerce order, falling back to direct detection.
	 * 
	 * @since 1.0.0
	 * @param \WC_Order $order The WooCommerce order object.
	 * @return string The client's IP address.
	 */
	private function client_ip_from_order($order){
		$ip=$order->get_customer_ip_address(); return $ip?$ip:$this->client_ip();
	}

	/**
	 * Check if an IP address is within a given CIDR range.
	 * 
	 * @since 1.0.0
	 * @param string $ip   The IP address to check.
	 * @param string $cidr The CIDR range
	 * @return bool True if the IP is in the range, false otherwise.
	 */
	private function ip_in_cidr($ip,$cidr){
		if(strpos($cidr,'/')===false) return $ip===$cidr;
		list($sub,$mask)=explode('/',$cidr); $mask=(int)$mask; $ipl=ip2long($ip); $s=ip2long($sub); if($ipl===false||$s===false) return false;
		$m=-1 << (32-$mask); return (($ipl & $m)===($s & $m));
	}

	/**
	 * JavaScript snippet to set the required cookie for JS challenge.
	 * 
	 * @since 1.0.0
	 * @return string JavaScript code to set the cookie.
	 */
	private function js_challenge(){
		$c=esc_js(get_option(SWFO_Opt::k('required_cookie'),'swfo_js'));
		return "(function(){try{var n='{$c}',v=Math.random().toString(36).slice(2,10),d=new Date();d.setTime(d.getTime()+5*60*1000);document.cookie=n+'='+v+'; path=/; expires='+d.toUTCString()+'; SameSite=Lax';}catch(e){}})();";
	}

	/**
	 * Issue a simple math CAPTCHA challenge.
	 * * Generates two random operands (3-9 and 2-8) and a random operator (+, -, *).
	 * * Creates a nonce tied to the specific challenge for stateless verification.
	 * * Returns an array with operands, operator, question string, and nonce.
	 * @since 2.0.0
	 * @return array Associative array with keys:
	 *               - 'a'  (int)    First operand.
	 *               - 'b'  (int)    Second operand.
	 *               - 'op' (string) Operator ('+', '-', '*').
	 *               - 'q'  (string) Question string (e.g., "3 + 4").
	 *               - 'n'  (string) Nonce for verification.
	 */ 
	private function captcha_issue(){
		$a = rand(3,9);
		$b = rand(2,8);
		$ops = ['+','-','*'];
		$op = $ops[array_rand($ops)];
		$nonce = wp_create_nonce('swfo_cpt_'.$a.'_'.$b.'_'.$op);
		return ['a'=>$a,'b'=>$b,'op'=>$op,'q'=>"$a $op $b",'n'=>$nonce];
	}

	/**
	 * Verify the answer to a math CAPTCHA challenge.
	 * 
	 * Validates the provided answer against the expected result based on the
	 * operands and operator encoded in the nonce. Returns true if the answer
	 * is correct and the nonce is valid; false otherwise.
	 * 
	 * @since 2.0.0
	 * @param string|int $ans   The user's answer to verify.
	 * @param string     $nonce The nonce received with the challenge.
	 * @param string     $op    The operator used in the challenge ('+', '-', '*').
	 * @return bool True if the answer is correct and nonce is valid, false otherwise.
	 */
	private function captcha_verify($ans, $nonce, $op = '+'){
		if(!$ans || !$nonce) return false;
		$ans = (int) $ans;
		for($a=3;$a<=9;$a++){
			for($b=2;$b<=8;$b++){
				foreach(['+','-','*'] as $o){
					if ( wp_verify_nonce($nonce, 'swfo_cpt_'.$a.'_'.$b.'_'.$o) ){
						$exp = ($o==='+') ? ($a+$b) : (($o==='-')?($a-$b):($a*$b));
						return $ans === $exp;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Add a "Settings" link to the plugin entry on the Plugins page.
	 *
	 * @since 1.0.0
	 * @param array $links Existing plugin action links.
	 * @return array Modified plugin action links with "Settings" prepended.
	 */
	function links($links){ array_unshift($links,'<a href="'.admin_url('admin.php?page=swfo').'">Settings</a>'); return $links; }

	/**
	 * Log REST API hits to a Redis list or transient ring buffer.
	 *
	 * Captures details of each REST request (path, method, IP, user agent,
	 * parameters) and stores them in a Redis list (preferred) or a transient
	 * array. Respects the master enable/disable switch and caps the payload
	 * size to ~6KB per entry. Configurable maximum number of entries is
	 * controlled by the `api_hits_max` option (default 1000).
	 *
	 * @since 2.0.0
	 *
	 * @param mixed               $result  The response to be sent to the client.
	 * @param \WP_REST_Server     $handler The REST server instance.
	 * @param \WP_REST_Request    $request The REST request object.
	 * @return mixed The original $result, unmodified.
	 */
	public function rest_hit_logger($result, $handler, $request){
		// Respect master switch + ensure request object
		if ( ! get_option(SWFO_Opt::k('enable_api_hit_logging'), true) ) return $result;
		if ( ! ($request instanceof WP_REST_Request) ) return $result;

		// Only log REST (wp-json) traffic; this filter runs only for REST so it's okay.
		$ip     = $this->client_ip();
		$route  = $request->get_route();                 // e.g. /wc/v3/orders
		$path   = '/wp-json' . $route;                   // full REST path
		$ua     = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$method = $request->get_method();
		$params = $this->mask_sensitive($request->get_params());

		$entry = [
			't'      => time(),
			'ip'     => $ip,
			'm'      => $method,
			'path'   => $path,
			'route'  => $route,
			'ua'     => mb_substr($ua, 0, 300),
			'data'   => $this->truncate_json($params, 6000), // cap payload ~6KB per entry
		];

		$this->api_hits_push($entry);
		return $result;
	}

	/**
	 * Push a new API hit entry to storage (Redis or transient).
	 *
	 * Attempts to push to a Redis list `swfo:api_hits` first, trimming to
	 * the configured maximum length. On Redis failure, falls back to a
	 * transient array keyed by {@see SWFO_Opt::k('api_hits')}, trimming as needed.
	 * @since 2.0.0
	 * @param array $entry Associative array representing the API hit entry.
	 *                     Expected keys:
	 *                     - 't'      (int)    Unix timestamp.
	 *                     - 'ip'     (string) Client IP address.
	 *                     - 'm'      (string) HTTP method (e.g., GET, POST).
	 *                     - 'path'   (string) Full REST path (e.g., /wp-json/wc/v3/orders).
	 *                     - 'route'  (string) REST route (e.g., /wc/v3/orders).
	 *                     - 'ua'		 (string) User agent string.
	 *                     - 'data'   (mixed) Request parameters (array/object).
	 * @return void
	 */
	private function api_hits_push(array $entry){
		$max = max(100, (int) get_option(SWFO_Opt::k('api_hits_max'), 1000));
		if ($this->use_redis && $this->redis){
			try{
				$key='swfo:api_hits';
				$this->redis->lPush($key, wp_json_encode($entry));
				$this->redis->lTrim($key, 0, $max-1);
				return;
			}catch(\Throwable $e){
				error_log('SWFO Redis hits_push fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		$key = SWFO_Opt::k('api_hits');
		$hits = get_transient($key);
		if (!is_array($hits)) $hits = [];
		array_unshift($hits, $entry);
		$hits = array_slice($hits, 0, $max);
		set_transient($key, $hits, DAY_IN_SECONDS);
	}

	/**
	 * Retrieve stored API hit entries from Redis or transient.
	 * 
	 * Attempts to read from a Redis list `swfo:api_hits` first, decoding each
	 * JSON entry. On Redis failure, falls back to a transient array keyed by
	 * {@see SWFO_Opt::k('api_hits')}. Always returns an array of entries, or
	 * an empty array if none are present.
	 *
	 * @since 2.0.0
	 * @return array[] Array of API hit entries. Each entry is an associative array with
	 * 							 keys:
	 * 							- 't'      (int)    Unix timestamp.
	 * 							- 'ip'     (string) Client IP address.
	 * 							- 'm'      (string) HTTP method (e.g., GET, POST).
	 * 							- 'path'   (string) Full REST path (e.g., /wp-json/wc/v3/orders).
	 * 							- 'route'	(string) REST route (e.g., /wc/v3/orders).
	 * 							- 'ua'		 (string) User agent string.
	 * 							- 'data'   (mixed) Request parameters (array/object).
	 */
	private function api_hits_get(){
		if ($this->use_redis && $this->redis){
			try{
				$list = $this->redis->lRange('swfo:api_hits', 0, -1);
				if (!is_array($list)) $list=[];
				$out=[];
				foreach($list as $row){ $dec=json_decode($row,true); if(is_array($dec)&&isset($dec['t'])) $out[]=$dec; }
				return $out;
			}catch(\Throwable $e){
				error_log('SWFO Redis hits_get fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		$hits = get_transient(SWFO_Opt::k('api_hits'));
		return is_array($hits) ? $hits : [];
	}

	/**
	 * Clear all stored API hit entries from Redis or transient.
	 * 
	 * Attempts to delete the Redis list `swfo:api_hits` first; on failure
	 * or when Redis is not in use, deletes the corresponding transient.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	private function api_hits_clear(){
		if ($this->use_redis && $this->redis){
			try{ $this->redis->del('swfo:api_hits'); return; }
			catch(\Throwable $e){ error_log('SWFO Redis hits_clear fallback: '.$e->getMessage()); $this->use_redis=false; }
		}
		delete_transient(SWFO_Opt::k('api_hits'));
	}

	/**
	 * Export API hits as a CSV file (from admin button).
	 * 
	 * Checks permissions and nonce, retrieves all hits, and streams a CSV
	 * download with appropriate headers. Each row contains:
	 * - datetime (Y-m-d H:i:s)
	 * - ip
	 * - method
	 * - path
	 * - route
	 * - user_agent
	 * - data (JSON-encoded parameters)
	 * 
	 * @since 2.0.0
	 * @return void (exits after output)
	 */
	public function handle_export_api_hits(){
		if (!current_user_can('manage_options')) wp_die('Forbidden');
		check_admin_referer('swfo_export_hits');

		$hits = $this->api_hits_get();
		$filename = 'swfo_api_hits_' . date('Ymd_His') . '.csv';

		header('Content-Type: text/csv; charset=utf-8');
		header('Content-Disposition: attachment; filename='.$filename);

		$out = fopen('php://output', 'w');
		// Header
		fputcsv($out, ['datetime','ip','method','path','route','user_agent','data']);
		foreach ($hits as $h){
			fputcsv($out, [
				date('Y-m-d H:i:s', (int)$h['t']),
				$h['ip'] ?? '',
				$h['m'] ?? '',
				$h['path'] ?? '',
				$h['route'] ?? '',
				$h['ua'] ?? '',
				is_array($h['data']) ? wp_json_encode($h['data']) : (string)($h['data'] ?? '')
			]);
		}
		fclose($out);
		exit;
	}

	/**
	 * Clear all stored API hit entries (from admin button).
	 * 
	 * Checks permissions and nonce, clears all hits, then redirects back
	 * to the settings page with the #apihits tab.
	 * 
	 * @since 2.0.0
	 * @return void (exits after redirect)
	 */
	public function handle_clear_api_hits(){
		if (!current_user_can('manage_options')) wp_die('Forbidden');
		check_admin_referer('swfo_clear_hits');
		$this->api_hits_clear();
		wp_redirect(admin_url('admin.php?page=swfo#apihits'));
		exit;
	}

	/**
	 * Recursively mask sensitive fields in an array or object.
	 * 
	 * Scans the input for keys commonly associated with sensitive data
	 * (e.g., 'password', 'token', 'api_key') and replaces their values with '***'.
	 * Works recursively on nested arrays and objects. Leaves primitive values unchanged.
	 * @since 2.0.0
	 * @param mixed $val The input value (array, object, or primitive).
	 * @return mixed The input with sensitive fields masked.
	 */
	private function mask_sensitive($val){
		$keys = ['password','pass','pwd','secret','token','api_key','apikey','key','authorization','auth','hmac','signature','x-wc-api-key','x-wc-hmac'];
		if (is_array($val)){
			$out = [];
			foreach ($val as $k=>$v){
				if (is_string($k) && in_array(strtolower($k), $keys, true)){
					$out[$k] = '***';
				}else{
					$out[$k] = $this->mask_sensitive($v);
				}
			}
			return $out;
		}
		if (is_object($val)){
			foreach($val as $k=>$v){
				if (is_string($k) && in_array(strtolower($k), $keys, true)){
					$val->$k = '***';
				}else{
					$val->$k = $this->mask_sensitive($v);
				}
			}
			return $val;
		}
		// primitives unchanged
		return $val;
	}

	/**
	 * Truncate a data structure to a JSON string of limited length.
	 * 
	 * Encodes the input as JSON and checks its length. If it exceeds
	 * the specified limit, truncates the JSON string to that length
	 * and attempts to decode it back to an array. If decoding fails,
	 * returns a placeholder array indicating truncation. If within
	 * the limit, returns the original data unchanged.
	 * 
	 * @since 2.0.0
	 * @param mixed $data  The input data (array/object).
	 * @param int   $limit Maximum allowed length of the JSON string.
	 * @return mixed The original data if within limit, or a truncated version.
	 */
	private function truncate_json($data, $limit){
		$json = wp_json_encode($data);
		if ($json === null) return $data;
		if (strlen($json) <= $limit) return $data;
		// hard truncate: note this is just for display/logging compactness
		return json_decode(substr($json, 0, $limit), true) ?: ['_truncated_' => true];
	}

	/**
	 * Paginate an array of items.
	 *
	 * @since 1.0.0
	 * @param array $items    The full array of items to paginate.
	 * @param int   $page     The current page number (1-based).
	 * @param int   $per_page Number of items per page.
	 * @return array Tuple of (paged items array, current page, total pages, total
	 * 							items).
	 */
	private function paginate_array(array $items, int $page, int $per_page){
		$total = count($items);
		$pages = max(1, (int)ceil($total / max(1,$per_page)));
		$page  = min(max(1,$page), $pages);
		$offs  = ($page - 1) * $per_page;
		return [ array_slice($items, $offs, $per_page), $page, $pages, $total ];
	}

	/**
	 * Generate a URL for a specific admin tab with optional query args.
	 *
	 * @since 1.0.0
	 * @param string $tab  The tab identifier (e.g., 'settings', 'logs').
	 * @param array  $args Optional associative array of additional query args.
	 * @return string The generated URL.
	 */
	private function tab_url($tab, array $args = []){
		$base = admin_url('admin.php?page=swfo');
		if(!empty($args)) $base = add_query_arg($args, $base);
		return $base . '#' . rawurlencode($tab);
	}

	/**
	 * Render pagination controls for admin tables.
	 *
	 * Outputs HTML for pagination controls, including First/Prev and Next/Last
	 * buttons, and a status indicator. Disables buttons as appropriate. Uses
	 * the provided tab and page argument name to construct URLs. Accepts extra
	 * query args to preserve in the links.
	 *
	 * @since 1.0.0
	 *
	 * @param string $tab      The current tab identifier.
	 * @param string $arg_page The name of the page number query argument.
	 * @param int    $page     The current page number (1-based).
	 * @param int    $pages    The total number of pages.
	 * @param array  $extra    Optional associative array of additional query args to preserve.
	 * @return void Outputs HTML directly.
	 */
	private function render_pager($tab, $arg_page, $page, $pages, array $extra = []){
		if($pages <= 1) return;
		$q = array_merge(['swfo_tab'=>$tab], $extra);
		echo '<div class="tablenav"><div class="tablenav-pages">';
		// First / Prev
		if($page > 1){
			echo '<a class="button" href="'.esc_url($this->tab_url($tab, array_merge($q, [$arg_page=>1]))).'">&laquo; First</a> ';
			echo '<a class="button" href="'.esc_url($this->tab_url($tab, array_merge($q, [$arg_page=>($page-1)]))).'">&lsaquo; Prev</a> ';
		} else {
			echo '<span class="button disabled">&laquo; First</span> <span class="button disabled">&lsaquo; Prev</span> ';
		}
		// status
		echo '<span class="tablenav-pages-navspan" style="margin:0 8px;">Page '.intval($page).' of '.intval($pages).'</span>';
		// Next / Last
		if($page < $pages){
			echo '<a class="button" href="'.esc_url($this->tab_url($tab, array_merge($q, [$arg_page=>($page+1)]))).'">Next &rsaquo;</a> ';
			echo '<a class="button" href="'.esc_url($this->tab_url($tab, array_merge($q, [$arg_page=>$pages]))).'">Last &raquo;</a>';
		} else {
			echo '<span class="button disabled">Next &rsaquo;</span> <span class="button disabled">Last &raquo;</span>';
		}
		echo '</div></div>';
	}
}

/**
 * Bootstrap the plugin.
 */
add_action('plugins_loaded', ['SWFO_Plugin','boot']);
