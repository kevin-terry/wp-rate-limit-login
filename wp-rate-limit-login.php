<?php
/**
 * Plugin Name: Rate Limit Login
 * Description: Lightweight login rate limiter using transients. Drop in wp-content/mu-plugins/.
 * Version: 1.0.0
 */

defined('ABSPATH') || exit;

/**
 * Configuration
 *
 * Adjust these values to suit your needs.
 * - MAX_ATTEMPTS: Failed logins allowed before lockout.
 * - LOCKOUT_DURATION: Seconds the IP is blocked after exceeding max attempts.
 * - DECAY_DURATION: Seconds before the failed attempt counter resets (sliding window).
 */
define('RLL_MAX_ATTEMPTS',    5);
define('RLL_LOCKOUT_DURATION', 900);  // 15 minutes
define('RLL_DECAY_DURATION',   600);  // 10 minutes

/**
 * Get the client IP address.
 *
 * Uses REMOTE_ADDR only — header-based IPs (X-Forwarded-For, etc.)
 * are trivially spoofable and unreliable for security decisions.
 * If you're behind a trusted reverse proxy (e.g. Cloudflare), you
 * can swap this to the appropriate header.
 */
function rll_get_client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Build the transient key for a given IP.
 *
 * Uses a hash to keep the key short and avoid special characters.
 */
function rll_transient_key(string $ip): string {
    return 'rll_' . substr(md5($ip), 0, 12);
}

/**
 * Check if the current IP is locked out before WordPress processes the login.
 *
 * Hooked to 'login_init' — fires early on the login page, before
 * authentication runs. If the IP is locked, we bail immediately
 * with a 429 response.
 */
function rll_check_lockout(): void {

    // Only rate-limit POST requests (actual login attempts).
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $ip  = rll_get_client_ip();
    $key = rll_transient_key($ip);

    $data = get_transient($key);

    if ($data === false) {
        return;
    }

    // IP is in an active lockout period.
    if (!empty($data['locked'])) {
        rll_send_429($data['locked']);
    }
}
add_action('login_init', 'rll_check_lockout', 1);

/**
 * Record a failed login attempt.
 *
 * Increments the counter for the IP. If the threshold is exceeded,
 * sets a lockout flag with its own expiry.
 */
function rll_record_failed_attempt(string $username): void {

    $ip  = rll_get_client_ip();
    $key = rll_transient_key($ip);

    $data = get_transient($key);

    if ($data === false) {
        $data = ['attempts' => 0];
    }

    $data['attempts']++;

    if ($data['attempts'] >= RLL_MAX_ATTEMPTS) {
        $data['locked'] = time() + RLL_LOCKOUT_DURATION;
        set_transient($key, $data, RLL_LOCKOUT_DURATION);
    } else {
        set_transient($key, $data, RLL_DECAY_DURATION);
    }
}
add_action('wp_login_failed', 'rll_record_failed_attempt', 10, 1);

/**
 * Clear the counter on successful login.
 *
 * No reason to keep tracking an IP that authenticated successfully.
 */
function rll_clear_on_success(string $username, \WP_User $user): void {

    $ip  = rll_get_client_ip();
    $key = rll_transient_key($ip);

    delete_transient($key);
}
add_action('wp_login', 'rll_clear_on_success', 10, 2);

/**
 * Send a 429 Too Many Requests response and stop execution.
 *
 * Includes a Retry-After header so well-behaved clients know
 * when to try again.
 */
function rll_send_429(int $locked_until): void {

    $retry_after = max(1, $locked_until - time());

    status_header(429);
    header('Retry-After: ' . $retry_after);
    header('Content-Type: text/plain; charset=UTF-8');

    echo 'Too many login attempts. Please try again in ' . ceil($retry_after / 60) . ' minute(s).';
    exit;
}
