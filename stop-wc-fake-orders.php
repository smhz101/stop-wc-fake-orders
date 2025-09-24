<?php
/*
Plugin Name: Stop WooCommerce Fake Orders
Description: Edge gate + IP/CIDR allowlist + optional HMAC + Redis-backed IP/email rate limits/bans + REST abuse protection + JS cookie + honeypot + success-resets + admin UI + logs export + per-route exemptions + header bypass + optional CAPTCHA-after-soft-block + CIDR soft deny (429). Single file.
Version: 2.1.0
Author: Muzammil
License: GPLv2+
*/

if (!defined('ABSPATH')) exit;

/** ===== Constants (safe defaults; can be overridden via wp-config.php) ===== */
if (!defined('SWFO_PREFIX')) define('SWFO_PREFIX', 'swfo_');
if (!defined('SWFO_SOFT_DENY_429')) define('SWFO_SOFT_DENY_429', true); // soft deny (429) for CIDR/country lists
// Redis auth/db constants (preferred for secrets; options UI also supported)
if (!defined('SWFO_USE_REDIS')) define('SWFO_USE_REDIS', false); // set true in wp-config for prod if phpredis is installed
if (!defined('SWFO_REDIS_AUTH')) define('SWFO_REDIS_AUTH', '');  // e.g. 'mySecretPass' (leave '' if none)
if (!defined('SWFO_REDIS_DB'))   define('SWFO_REDIS_DB', 0);     // e.g. 0..15

/** ===== Option helper ===== */
class SWFO_Opt { static function k($n){ return SWFO_PREFIX.$n; } }

/** ===== Main ===== */
class SWFO_Plugin {
	private static $inst;
	private $redis=null,$use_redis=false;
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

	static function boot(){ if(!self::$inst){ self::$inst=new self; self::$inst->init(); } return self::$inst; }

	function init(){
		// Add contextual help tabs for this admin screen
		add_action('load-woocommerce_page_swfo', [$this,'add_help_tabs']);
		
		// Core hooks
		add_action('admin_notices', [$this,'maybe_wc_notice']);
		add_action('admin_init', [$this,'ensure_defaults']);
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

		// wp-config constants appender
		add_action('admin_init', [$this,'maybe_write_wp_config_constants']);

		// Settings link
		add_filter('plugin_action_links_'.plugin_basename(__FILE__), [$this,'links']);

		// Log ALL wp-json (REST) hits early, before gating decisions (runs on every REST request)
		add_filter('rest_request_before_callbacks', [$this,'rest_hit_logger'], 1, 3);

		// Admin actions for API hits (CSV export / clear)
		add_action('admin_post_swfo_export_hits', [$this,'handle_export_api_hits']);
		add_action('admin_post_swfo_clear_hits',  [$this,'handle_clear_api_hits']);

		add_action('admin_enqueue_scripts', function($hook){
			if ($hook === 'woocommerce_page_swfo') {
				wp_register_script('chartjs', 'https://cdn.jsdelivr.net/npm/chart.js', [], null, true);
			}
		});
	}

	/**
	 * Add contextual Help Tabs to the Stop Fake Orders admin screen.
	 * Explains impact of options without cluttering the form.
	 */
	public function add_help_tabs(){
		$screen = get_current_screen();
		if ( ! $screen || $screen->id !== 'woocommerce_page_swfo' ) return;

		$screen->add_help_tab([
			'id'      => 'swfo_overview',
			'title'   => __('Overview','default'),
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
			'title' => __('Rate Limiting','default'),
			'content' =>
				'<p><strong>Window (sec)</strong> defines the sliding window length. '.
				'<strong>IP requests/window</strong> caps how many REST calls per IP. '.
				'<strong>Email submits/window</strong> caps how many order attempts per email.</p>'.
				'<p>With Redis enabled, counters are scalable (INCR/EXPIRE). Without Redis, transients approximate the same behavior.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_gates',
			'title' => __('Edge Gate & Identity','default'),
			'content' =>
				'<p>Use <code>X-WC-API-Key</code> for server-to-server requests. Keys are stored hashed. '.
				'Optional HMAC (<code>X-WC-HMAC</code>, <code>X-WC-Timestamp</code>) deters key replay within ±5 minutes. '.
				'Bypass tokens (<code>X-SWFO-Bypass</code>) are for trusted backend jobs to skip browser checks.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_browser',
			'title' => __('Browser Challenges','default'),
			'content' =>
				'<p><strong>JS cookie</strong> verifies a real browser is present. <strong>Honeypot</strong> blocks naive bots. '.
				'Enable <strong>CAPTCHA</strong> only after repeated soft blocks to minimize friction for legit buyers.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_lists',
			'title' => __('Allow/Deny Lists','default'),
			'content' =>
				'<p><strong>Allowlist CIDRs</strong> fully bypass protections (trusted partners). '.
				'<strong>Soft-deny CIDRs</strong> respond with HTTP 429 (not 403) to discourage probing. '.
				'<strong>UA denylist</strong> rejects known bad user agents.</p>'
		]);

		$screen->add_help_tab([
			'id'    => 'swfo_telemetry',
			'title' => __('Logs & Export','default'),
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

	/** ===== WooCommerce presence (soft check) ===== */
	function maybe_wc_notice(){
		if( is_admin() && current_user_can('manage_options') && !class_exists('WooCommerce') ){
			echo '<div class="notice notice-warning"><p><strong>Stop WooCommerce Fake Orders</strong> works best with WooCommerce active.</p></div>';
		}
	}

	/** ===== Defaults ===== */
	function ensure_defaults(){
		if(!get_option(SWFO_Opt::k('configured'))){
			foreach($this->defaults as $k=>$v) if(false===get_option(SWFO_Opt::k($k))) update_option(SWFO_Opt::k($k), $v);
			update_option(SWFO_Opt::k('configured'),1);
		}
	}

	/** ===== Redis ===== */
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

	/** ===== Admin ===== */
	function menu(){
		add_submenu_page('woocommerce','Stop Fake Orders','Stop Fake Orders','manage_options','swfo',[$this,'admin_page']);
	}

	/**
	 * Admin page with native WP tabs (no reload). Hash-based routing preserves active tab on refresh.
	 * All settings live in a single <form>; switching tabs is JS-only.
	 */
	function admin_page(){
		if(!current_user_can('manage_options')) return;

		// Save + feedback (redirect back to current tab)
		if ( isset($_POST['swfo_save']) && check_admin_referer('swfo_save', 'swfo_nonce') ) {
			$this->save_settings();
			$this->setup_redis();
			$tab = isset($_POST['swfo_tab']) ? sanitize_text_field($_POST['swfo_tab']) : 'status';
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
				$ev_q    = isset($_GET['events_q'])    ? sanitize_text_field($_GET['events_q'])    : '';
				$ev_type = isset($_GET['events_type']) ? sanitize_text_field($_GET['events_type']) : '';
				$ev_p    = isset($_GET['events_p'])    ? max(1, intval($_GET['events_p']))         : 1;

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
						<tbody>
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
				$h_q   = isset($_GET['hits_q'])   ? sanitize_text_field($_GET['hits_q'])   : '';
				$h_ip  = isset($_GET['hits_ip'])  ? sanitize_text_field($_GET['hits_ip'])  : '';
				$h_m   = isset($_GET['hits_m'])   ? strtoupper(sanitize_text_field($_GET['hits_m'])) : '';
				$h_p   = isset($_GET['hits_p'])   ? max(1, intval($_GET['hits_p'])) : 1;

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
						<tbody>
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

	/** ===== Save settings ===== */

	function save_settings(){
		$fields = [
			'window_seconds','ip_rate_limit','email_rate_limit','required_cookie','hmac_secret','redis_host','redis_port','logs_max','webhook_url','captcha_after_soft_blocks'
		];
		foreach($fields as $f){
			if(isset($_POST[$f])) update_option(SWFO_Opt::k($f), is_numeric($_POST[$f])?intval($_POST[$f]):sanitize_text_field($_POST[$f]));
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
			$val = sanitize_text_field( wp_unslash($_POST['redis_auth']) );
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
			$m = sanitize_text_field($_POST['store_api_mode']);
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
	function handle_delete_key(){
		if(!current_user_can('manage_options') || !wp_verify_nonce($_GET['_wpnonce']??'','swfo_del_key')) wp_die('Forbidden');
		$id=sanitize_text_field($_GET['id']??'');
		$keys = get_option(SWFO_Opt::k('api_keys'),[]);
		if(isset($keys[$id])){ unset($keys[$id]); update_option(SWFO_Opt::k('api_keys'),$keys); }
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}
	function handle_add_bypass(){
		if ( ! current_user_can('manage_options') || ! check_admin_referer('swfo_add_bypass') ) wp_die('Forbidden');
		$name = sanitize_text_field($_POST['bp_name']??'bp_'.time());
		$tok  = trim($_POST['bp_token']??'');
		if($tok==='') $tok = bin2hex(random_bytes(16));
		$bp = get_option(SWFO_Opt::k('bypass_tokens'),[]);
		$bp[$name]=$tok;
		update_option(SWFO_Opt::k('bypass_tokens'),$bp);
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}
	function handle_delete_bypass(){
		if(!current_user_can('manage_options') || !wp_verify_nonce($_GET['_wpnonce']??'','swfo_del_bp')) wp_die('Forbidden');
		$name=sanitize_text_field($_GET['name']??'');
		$bp = get_option(SWFO_Opt::k('bypass_tokens'),[]);
		if(isset($bp[$name])){ unset($bp[$name]); update_option(SWFO_Opt::k('bypass_tokens'),$bp); }
		wp_redirect(admin_url('admin.php?page=swfo')); exit;
	}

	/** Return site host for same-origin checks */
	private function site_host(){
		$u = home_url('/');
		$p = parse_url($u);
		return isset($p['host']) ? strtolower($p['host']) : '';
	}

	/** Check if request Origin/Referer matches site host */
	private function is_same_origin($request){
		$site = $this->site_host();
		if(!$site) return false;
		$hdr = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
		if(!$hdr) return false;  // block when no Origin/Referer is sent
		$p = @parse_url($hdr);
		$h = isset($p['host']) ? strtolower($p['host']) : '';
		return $h === $site;
	}

	/** ===== REST Gate ===== */
	/**
	 * REST abuse gate.
	 * Filter signature: ($response, $handler, WP_REST_Request $request)
	 *
	 * @param WP_REST_Response|WP_Error|null $result
	 * @param array                          $handler
	 * @param WP_REST_Request                $request
	 * @return WP_REST_Response|WP_Error|null
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

	private function ban_key($type, $val){ return "ban:{$type}:".md5(strtolower(trim($val))); }

	public function ban_ip($ip, $ttl_seconds = 3600){
		$key = $this->ban_key('ip',$ip);
		if ($this->use_redis && $this->redis){
			$this->redis->setEx('swfo:'.$key, $ttl_seconds, 1);
		} else {
			set_transient('swfo_'.$key, 1, $ttl_seconds);
		}
		$this->log('ban_ip_set', "ip=$ip ttl=$ttl_seconds");
	}

	public function is_banned_ip($ip){
		$key = $this->ban_key('ip',$ip);
		if ($this->use_redis && $this->redis){
			return (bool) $this->redis->exists('swfo:'.$key);
		}
		return (bool) get_transient('swfo_'.$key);
	}

	public function ban_email($email, $ttl_seconds = 3600){
		$key = $this->ban_key('email',$email);
		if ($this->use_redis && $this->redis){
			$this->redis->setEx('swfo:'.$key, $ttl_seconds, 1);
		} else {
			set_transient('swfo_'.$key, 1, $ttl_seconds);
		}
		$this->log('ban_email_set', "email=$email ttl=$ttl_seconds");
	}

	public function is_banned_email($email){
		$key = $this->ban_key('email',$email);
		if ($this->use_redis && $this->redis){
			return (bool) $this->redis->exists('swfo:'.$key);
		}
		return (bool) get_transient('swfo_'.$key);
	}

	/** ===== Checkout Harden (forms) ===== */
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
	function enqueue_js(){
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

	/** Success resets: clear IP/email counters on legit success */
	function success_reset_by_order_id($order_id){
		if(!$order_id) return;
		$order = wc_get_order($order_id); if($order) $this->success_reset($order);
	}
	function success_reset_by_order_obj($order_id){
		$order = wc_get_order($order_id); if($order) $this->success_reset($order);
	}
	private function success_reset($order){
		$email = strtolower($order->get_billing_email());
		$ip = $this->client_ip_from_order($order);
		if($email) $this->reset('email:'.$email);
		if($ip) $this->reset('ip:'.$ip);
		$this->log('success_reset','email:'.$email.' ip:'.$ip);
	}

	/** ===== Helpers: keys, bypass, hmac ===== */
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
	private function api_ok($key){
		foreach((array)get_option(SWFO_Opt::k('api_keys'),[]) as $id=>$hash){
			if(password_verify($key,$hash)) return true;
		}
		return false;
	}
	private function bypass_ok($token){
		foreach((array)get_option(SWFO_Opt::k('bypass_tokens'),[]) as $n=>$t){
			if(hash_equals($t,$token)) return true;
		}
		return false;
	}
	private function hmac_ok($req,$h,$ts){
		$sec=get_option(SWFO_Opt::k('hmac_secret'),''); if(!$sec||!$h||!$ts) return false;
		if(abs(time()-intval($ts))>300) return false;
		$raw=$req->get_method().'|'.$req->get_route().'|'.$req->get_body().'|'.$ts;
		$calc=hash_hmac('sha256',$raw,$sec);
		return hash_equals($calc,$h);
	}

	/** ===== Counters (Redis or transients) ===== */
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

	private function reset($key){
		if($this->use_redis && $this->redis){
			try{ $this->redis->del('swfo:'.$key); return; }
			catch(\Throwable $e){ error_log('SWFO Redis reset fallback: '.$e->getMessage()); $this->use_redis=false; }
		}
		delete_transient('swfo_cnt_'.md5($key));
	}

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

	private function touch_fail($bucket,$ip){
		$win=intval(get_option(SWFO_Opt::k('window_seconds'),60));
		$c=$this->incr('soft:'.$ip,$win*10); // soft block counter lasts longer
		$this->log('soft_block',"$bucket ip=$ip c=$c");
	}

	/** ===== Logs (lightweight + export) ===== */

	private function logs_get(){
		if($this->use_redis && $this->redis){
			try{
				$raw=$this->redis->lRange('swfo:logs',0,-1);
				if(!is_array($raw)) $raw=[];
				$o=[];
				foreach($raw as $r){ $dec=@unserialize($r); if(is_array($dec)&&isset($dec['t'],$dec['type'])) $o[]=$dec; }
				return $o;
			}catch(\Throwable $e){
				error_log('SWFO Redis logs_get fallback: '.$e->getMessage());
				$this->use_redis=false;
			}
		}
		$l=get_transient(SWFO_Opt::k('logs'));
		return is_array($l)?$l:[];
	}
	
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

	private function log($type,$note=''){
		$l=$this->logs_get(); array_unshift($l,['t'=>time(),'type'=>$type,'note'=>$note]); $this->logs_set($l);
		if(get_option(SWFO_Opt::k('log_to_error_log'),false)) error_log("[SWFO] $type - $note");
		if($u=get_option(SWFO_Opt::k('webhook_url'),'')) $this->post_webhook($u, ['t'=>time(),'type'=>$type,'note'=>$note]);
	}
	private function post_webhook($url,$payload){ wp_remote_post($url,['timeout'=>2,'blocking'=>false,'headers'=>['Content-Type'=>'application/json'],'body'=>wp_json_encode($payload)]); }

	/** ===== Utils ===== */
	private function client_ip(){
		if(!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP']; // CF
		if(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){ $p=explode(',',$_SERVER['HTTP_X_FORWARDED_FOR']); return trim($p[0]); }
		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}
	private function client_ip_from_order($order){
		$ip=$order->get_customer_ip_address(); return $ip?$ip:$this->client_ip();
	}
	private function ip_in_cidr($ip,$cidr){
		if(strpos($cidr,'/')===false) return $ip===$cidr;
		list($sub,$mask)=explode('/',$cidr); $mask=(int)$mask; $ipl=ip2long($ip); $s=ip2long($sub); if($ipl===false||$s===false) return false;
		$m=-1 << (32-$mask); return (($ipl & $m)===($s & $m));
	}
	private function js_challenge(){
		$c=esc_js(get_option(SWFO_Opt::k('required_cookie'),'swfo_js'));
		return "(function(){try{var n='{$c}',v=Math.random().toString(36).slice(2,10),d=new Date();d.setTime(d.getTime()+5*60*1000);document.cookie=n+'='+v+'; path=/; expires='+d.toUTCString()+'; SameSite=Lax';}catch(e){}})();";
	}

	/** Simple math CAPTCHA (stateless-ish) */
	private function captcha_issue(){
		$a = rand(3,9);
		$b = rand(2,8);
		$ops = ['+','-','*'];
		$op = $ops[array_rand($ops)];
		$nonce = wp_create_nonce('swfo_cpt_'.$a.'_'.$b.'_'.$op);
		return ['a'=>$a,'b'=>$b,'op'=>$op,'q'=>"$a $op $b",'n'=>$nonce];
	}
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

	/** ===== wp-config editing (safe try) ===== */
	function maybe_write_wp_config_constants(){
		if(!is_admin()) return;
		$start="/* SWFO_CONSTANTS_START */"; $end="/* SWFO_CONSTANTS_END */";
		$snippet="\n$start\n".
			"define('SWFO_USE_REDIS', ".(get_option(SWFO_Opt::k('use_redis'),false)?'true':'false').");\n".
			"$end\n";
		$cfg=ABSPATH.'wp-config.php'; if(!file_exists($cfg)) return;
		$txt=@file_get_contents($cfg); if($txt===false || strpos($txt,$start)!==false) return;
		$needle="/* That's all, stop editing! Happy publishing. */";
		if(is_writable($cfg)){
			$pos=strpos($txt,$needle); $new = ($pos!==false)? substr_replace($txt,$snippet,$pos,0):($txt.$snippet);
			@copy($cfg, $cfg.'.bak_'.time()); @file_put_contents($cfg,$new);
			if(strpos(@file_get_contents($cfg),$start)===false){
				add_action('admin_notices', function()use($snippet){ echo '<div class="error"><p>SWFO: Could not write constants. Please paste:<pre>'.esc_html($snippet).'</pre></p></div>'; });
			}else{
				add_action('admin_notices', function(){ echo '<div class="updated"><p>SWFO: Constants added to wp-config.php (backup created).</p></div>'; });
			}
		}else{
			add_action('admin_notices', function()use($snippet){ echo '<div class="error"><p>SWFO recommends adding constants. Paste once into <code>wp-config.php</code>:<pre>'.esc_html($snippet).'</pre></p></div>'; });
		}
	}

	function links($links){ array_unshift($links,'<a href="'.admin_url('admin.php?page=swfo').'">Settings</a>'); return $links; }

	/**
	 * REST hit logger: records IP, time, method, route, UA, and sanitized params.
	 * NOTE: Always returns $result untouched.
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

	/** Push an API-hit entry into Redis list or transient ring buffer */

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

	/** Retrieve API hits (newest first). Always returns array. */
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

	/** Clear API hits */
	private function api_hits_clear(){
		if ($this->use_redis && $this->redis){
			try{ $this->redis->del('swfo:api_hits'); return; }
			catch(\Throwable $e){ error_log('SWFO Redis hits_clear fallback: '.$e->getMessage()); $this->use_redis=false; }
		}
		delete_transient(SWFO_Opt::k('api_hits'));
	}

	/** Export handler: CSV download of API hits */
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

	/** Clear handler (from admin button) */
	public function handle_clear_api_hits(){
		if (!current_user_can('manage_options')) wp_die('Forbidden');
		check_admin_referer('swfo_clear_hits');
		$this->api_hits_clear();
		wp_redirect(admin_url('admin.php?page=swfo#apihits'));
		exit;
	}

	/** Mask common sensitive fields recursively */
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

	/** Truncate nested JSON-ish payloads to a safe size budget */
	private function truncate_json($data, $limit){
		$json = wp_json_encode($data);
		if ($json === null) return $data;
		if (strlen($json) <= $limit) return $data;
		// hard truncate: note this is just for display/logging compactness
		return json_decode(substr($json, 0, $limit), true) ?: ['_truncated_' => true];
	}

	/** Simple array paginator */
	private function paginate_array(array $items, int $page, int $per_page){
		$total = count($items);
		$pages = max(1, (int)ceil($total / max(1,$per_page)));
		$page  = min(max(1,$page), $pages);
		$offs  = ($page - 1) * $per_page;
		return [ array_slice($items, $offs, $per_page), $page, $pages, $total ];
	}

	/** Build admin url with tab + args + hash */
	private function tab_url($tab, array $args = []){
		$base = admin_url('admin.php?page=swfo');
		if(!empty($args)) $base = add_query_arg($args, $base);
		return $base . '#' . rawurlencode($tab);
	}

	/** Render compact pagination (First/Prev/Next/Last) */
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
add_action('plugins_loaded', ['SWFO_Plugin','boot']);
