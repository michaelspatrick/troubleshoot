# Client Diagnostics Page (PHP)

This PHP script provides a simple diagnostic web page for collecting useful troubleshooting information from a user's browser and environment. It is designed to be placed on your website so you can send a link to users experiencing issues.

## Features

- **Client IP detection** (proxy-aware: checks `CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`, and falls back to `REMOTE_ADDR`)
- **User Agent details** with parsed **browser name/version** and **OS**
- **TLS/HTTPS details** (protocol, cipher)
- **Accepted languages** and **referrer**
- **All HTTP request headers**
- **Cloudflare info** — logs `cf-ray` and `cf-ipcountry` if present
- **JSON output** via `?json=1`
- **Logging** — writes JSON and human-readable formats to a log file
- **Copy button** for easy sharing
- **No-cache headers** to prevent caching in Cloudflare and browsers

## Installation

1. **Upload the script** to your web server, e.g.:
   ```bash
   scp client-diagnostics.php user@server:/var/www/html/
   ```

2. **Set permissions** so the server can write the log file:
   ```bash
   touch /var/www/html/client-diagnostics.log
   chown www-data:www-data /var/www/html/client-diagnostics.log   # or apache:apache on CentOS/RHEL
   chmod 664 /var/www/html/client-diagnostics.log
   ```

3. **Access in a browser**:
   ```
   https://yourdomain.com/client-diagnostics.php
   ```

4. **View JSON output**:
   ```
   https://yourdomain.com/client-diagnostics.php?json=1
   ```

## Preventing Caching (Cloudflare & Browsers)

The script sends strong cache-control headers to prevent caching:

```php
header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
header('Surrogate-Control: no-store');
header('CDN-Cache-Control: no-store');
```

If using Cloudflare's "Cache Everything," add a Page Rule or Cache Rule to bypass caching for this URL.

## Customization

At the top of the script, you can configure:

- `$logFile` — path to the log file
- `$resolveReverseDNS` — enable/disable reverse DNS lookup
- `$setTestCookie` — enable/disable cookie testing
- `$showAllHeaders` — toggle showing all request headers

## License

MIT License
