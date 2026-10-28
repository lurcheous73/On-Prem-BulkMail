<?php
declare(strict_types=1);

/** Request timing only. Never log a URL, credential, session ID, identity or error message. */
function bm_request_diagnostic(string $stage, ?string $reason = null): void {
    static $started = null;
    static $previous = 'ingress';
    $stages = ['ingress','session_ready','session_skipped_broker','database_ready','schema_ready','broker_dispatch',
        'session_validation_start','session_validation_failed','session_validation_complete',
        'auto_login_gate','auto_login_complete','shutdown'];
    if (!in_array($stage, $stages, true)) return;
    if ($started === null) {
        $started = hrtime(true);
        register_shutdown_function(static function (): void { bm_request_diagnostic('shutdown'); });
    }
    $page = $_GET['page'] ?? 'home';
    $routes = ['home','login','logout','portal_sso_authorize','portal_sso_token'];
    $method = $_SERVER['REQUEST_METHOD'] ?? null;
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    $record = [
        'stage'=>$stage,
        'route'=>in_array($page, $routes, true) ? $page : 'other',
        'pid'=>max(0, (int)getmypid()),
        'elapsed_ms'=>min(3600000, max(0, (int)round((hrtime(true)-$started)/1000000))),
        'method'=>in_array($method, ['GET','POST','HEAD'], true) ? $method : 'other',
        'portal_cookie_present'=>array_key_exists('asc_auth_key', $_COOKIE),
        'session_cookie_present'=>array_key_exists(session_name(), $_COOKIE),
        'fetch_dest'=>$dest === null ? 'missing' : (in_array($dest, ['document','iframe','empty'], true) ? $dest : 'other'),
        'fetch_site'=>$site === null ? 'missing' : (in_array($site, ['same-origin','same-site','cross-site','none'], true) ? $site : 'other'),
    ];
    if ($reason !== null) {
        $reasons = ['eligible','method_not_get','session_present','logout_suppressed','route_excluded',
            'integration_disabled','auto_login_disabled','portal_session_rejected','login_established','login_unavailable'];
        $record['reason'] = in_array($reason, $reasons, true) ? $reason : 'other';
    }
    if ($stage === 'shutdown') {
        $status = http_response_code();
        $record['last_stage'] = $previous;
        $record['http_status'] = is_int($status) && $status >= 100 && $status <= 599 ? $status : 0;
        $record['connection_aborted'] = connection_aborted() === 1;
        $record['fatal_error'] = in_array(error_get_last()['type'] ?? null,
            [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR,E_USER_ERROR,E_RECOVERABLE_ERROR], true);
    } else $previous = $stage;
    // Every string above is an allowlisted literal. A diagnostic failure must
    // not alter response handling or the existing session/authentication flow.
    error_log('BulkMail request bootstrap '.json_encode($record));
}
