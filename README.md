# Rate Limit WordPress Logins

A lightweight WordPress must-use plugin that rate limits login attempts by IP address. No admin UI, no database tables, no bloat — just a single file using WordPress transients.

## Why

WordPress doesn't limit login attempts by default. If your login endpoint is exposed, bots can hammer it indefinitely. Most security plugins that solve this come bundled with dozens of unrelated features.

This plugin does one thing: block an IP after too many failed login attempts.

## How It Works

- Failed login attempts are tracked per IP using WordPress transients.
- After **5 failed attempts** within a **10-minute window**, the IP is locked out for **15 minutes**.
- Locked IPs receive an HTTP `429 Too Many Requests` response with a `Retry-After` header.
- Only `POST` requests are counted — visiting the login page doesn't trigger the limiter.
- Successful login clears the counter for that IP.

If your site has Memcached or Redis object caching enabled, transients are stored in memory and the overhead is effectively zero.

## Installation

Copy `rate-limit-login.php` into your `wp-content/mu-plugins/` directory. Create the directory if it doesn't exist.

```
wp-content/
└── mu-plugins/
    └── rate-limit-login.php
```

Must-use plugins load automatically. No activation required.

## Configuration

Adjust the constants at the top of the file:

| Constant | Default | Description |
|---|---|---|
| `RLL_MAX_ATTEMPTS` | `5` | Failed attempts allowed before lockout |
| `RLL_LOCKOUT_DURATION` | `900` | Lockout length in seconds (15 min) |
| `RLL_DECAY_DURATION` | `600` | Window before the attempt counter resets (10 min) |

## IP Detection

The plugin uses `REMOTE_ADDR` by default, which is the only reliable source when not behind a trusted proxy. If your site is behind Cloudflare, swap `rll_get_client_ip()` to read from the `CF-Connecting-IP` header:

```php
function rll_get_client_ip(): string {
    return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
```

## Testing

1. Navigate to your login page.
2. Submit incorrect credentials 5 times.
3. On the 6th attempt you should receive a `429 Too Many Requests` response.
4. After 15 minutes (or the configured lockout duration), access is restored.

## Compatibility

- WordPress 5.0+
- PHP 7.4+
- Works with standard and non-standard login paths (e.g. Bedrock, custom `/wordpress/` subdirectory installs).
- Compatible with NGINX Direct Delivery (SiteGround) since PHP requests are processed by Apache regardless.

## License

MIT
