<?php
declare(strict_types=1);

/* UK English spell-check API for The Grange Bulk Mail. */
if (($page ?? '') === 'spellcheck_api') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit;
    }

    check_csrf();
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    $text = (string)($_POST['text'] ?? '');
    if (mb_strlen($text, 'UTF-8') > 50000) {
        $text = mb_substr($text, 0, 50000, 'UTF-8');
    }

    $text = html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace('#https?://\S+|\b\S+@\S+\b#iu', ' ', $text);
    $text = preg_replace('/[^\p{L}\p{M}\'’-]+/u', "\n", $text);

    $cmd = ['/usr/bin/hunspell', '-d', 'en_GB', '-a', '-i', 'UTF-8'];
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $proc = proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Spell checker is unavailable.']);
        exit;
    }

    fwrite($pipes[0], $text);
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $error = trim((string)stream_get_contents($pipes[2]));
    fclose($pipes[2]);
    $rc = proc_close($proc);

    if ($rc !== 0 && $output === '') {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => $error ?: 'Spell checker failed.']);
        exit;
    }

    $issues = [];
    $seen = [];

    foreach (preg_split('/\R/u', (string)$output) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '@(#)')) {
            continue;
        }

        $word = '';
        $suggestions = [];

        if (preg_match('/^&\s+(\S+)\s+\d+\s+\d+:\s*(.*)$/u', $line, $m)) {
            $word = $m[1];
            $suggestions = array_values(array_filter(array_map('trim', explode(',', $m[2]))));
        } elseif (preg_match('/^#\s+(\S+)\s+\d+/u', $line, $m)) {
            $word = $m[1];
        } else {
            continue;
        }

        $key = mb_strtolower($word, 'UTF-8');
        if ($word === '' || isset($seen[$key]) || mb_strlen($word, 'UTF-8') < 2) {
            continue;
        }

        $seen[$key] = true;
        $issues[] = [
            'word' => $word,
            'suggestions' => array_slice($suggestions, 0, 6),
        ];

        if (count($issues) >= 100) {
            break;
        }
    }

    echo json_encode([
        'ok' => true,
        'language' => 'en-GB',
        'issues' => $issues,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
