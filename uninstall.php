<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

$prefix = defined('SWFO_PREFIX') ? SWFO_PREFIX : 'swfo_';

$options = array(
  'configured','api_keys','allowlist_cidrs','ua_denylist','required_cookie',
  'enable_js_challenge','enable_honeypot','enable_hmac','hmac_secret','window_seconds',
  'ip_rate_limit','email_rate_limit','logs_max','use_redis','redis_host','redis_port',
  'redis_auth','redis_db','log_to_error_log','webhook_url','captcha_enabled',
  'captcha_after_soft_blocks','bypass_tokens','soft_deny_cidrs','enable_api_hit_logging',
  'api_hits_max','store_api_write_rate_limit','store_api_mode','store_api_rate_limit',
  'logs','api_hits'
);

foreach ( $options as $k ) {
  delete_option( $prefix . $k );
}

// Also clear transients you create (patterns):
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_swfo_%' OR option_name LIKE '_transient_timeout_swfo_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_swfo_api_hit_%' OR option_name LIKE '_transient_timeout_swfo_api_hit_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'swfo_%'" );
