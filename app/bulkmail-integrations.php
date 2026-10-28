<?php
declare(strict_types=1);

/** Private, server-managed integration settings. Nothing here is configured by a request. */
function bm_integration_config(): array {
    $defaults = [
        'identity' => [
            'enabled' => false,
            'auto_login' => false,
            'base_url' => '',
            'directory_token' => '',
            'allow_http' => false,
            'session_ttl' => 3600,
            'portal_revalidate_seconds' => 60,
        ],
        'sms' => [
            'enabled' => false,
            'base_url' => '',
            'username' => '',
            'password' => '',
            'allow_http' => true,
            'min_interval_seconds' => 8,
        ],
        'whatsapp' => [
            'enabled' => false,
            'base_url' => 'http://127.0.0.1:8787',
            'token' => '',
            'allow_http' => true,
            'min_interval_seconds' => 8,
        ],
    ];
    $path = getenv('BULKMAIL_INTEGRATIONS_CONFIG') ?: '/etc/bulkmail/integrations.php';
    if (!is_file($path)) return $defaults;
    try {
        $configured = (static function (string $file) {
            // A malformed file without a PHP tag must not print its private contents.
            ob_start();
            try { return require $file; }
            finally { ob_end_clean(); }
        })($path);
        if (!is_array($configured)) throw new RuntimeException('Invalid integration configuration.');
        foreach ($defaults as $section => $values) {
            if (isset($configured[$section]) && !is_array($configured[$section])) {
                throw new RuntimeException('Invalid integration configuration section.');
            }
            $defaults[$section] = array_replace($values, $configured[$section] ?? []);
            // A literal boolean true is required; the string "false" must never enable sending.
            $defaults[$section]['enabled'] = ($defaults[$section]['enabled'] === true);
        }
        $defaults['identity']['auto_login'] = ($defaults['identity']['auto_login'] === true);
        return $defaults;
    } catch (Throwable $e) {
        // Local email and local login remain usable when an optional integration is misconfigured.
        // Do not expose paths, credentials, source code or provider responses to a browser.
        error_log('BulkMail: integrations configuration could not be loaded; integrations disabled.');
        foreach ($defaults as &$section) $section['enabled'] = false;
        unset($section);
        $defaults['identity']['auto_login'] = false;
        return $defaults;
    }
}

/** Validate an operator-supplied service origin; never follow redirects with credentials. */
function bm_integration_url(string $url, bool $allowHttp = false): string {
    $url = rtrim(trim($url), '/');
    $parts = parse_url($url);
    if (!$parts || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['query']) || isset($parts['fragment'])
        || !in_array(strtolower((string)($parts['scheme'] ?? '')), $allowHttp ? ['https','http'] : ['https'], true)
        || preg_match('/[\x00-\x20\x7f]/', $url)) {
        throw new RuntimeException('The integration service address is not configured correctly.');
    }
    return $url;
}
