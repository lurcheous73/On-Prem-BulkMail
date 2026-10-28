<?php
declare(strict_types=1);
require __DIR__.'/../app/bulkmail-integrations.php';
$path=tempnam(sys_get_temp_dir(),'bulkmail-config-');
putenv('BULKMAIL_INTEGRATIONS_CONFIG='.$path);
$checks=0;
function verify_config(string $name,bool $ok): void {
    global $checks;
    if (!$ok) throw new RuntimeException($name);
    $checks++; echo 'PASS '.$name.PHP_EOL;
}
try {
    file_put_contents($path,'private-token-with-missing-php-tag');
    ob_start(); $config=bm_integration_config(); $output=ob_get_clean();
    verify_config('Malformed private configuration never prints its contents',$output==='');
    verify_config('Malformed configuration disables all optional integrations',!$config['sms']['enabled']&&!$config['whatsapp']['enabled']&&!$config['identity']['enabled']);
    file_put_contents($path,'<?php echo "private-token"; return ["sms"=>["enabled"=>true]];');
    ob_start();$config=bm_integration_config();$output=ob_get_clean();
    verify_config('Accidental configuration output is suppressed without changing valid settings',$output===''&&$config['sms']['enabled']);
    file_put_contents($path,'<?php return ["sms"=>["enabled"=>"false"],"whatsapp"=>["enabled"=>1]];');
    $config=bm_integration_config();
    verify_config('String and integer switches cannot accidentally enable sending',!$config['sms']['enabled']&&!$config['whatsapp']['enabled']);
    file_put_contents($path,'<?php return broken syntax;');
    ob_start();$config=bm_integration_config();$output=ob_get_clean();
    verify_config('PHP configuration syntax failure stays private and fails closed',$output===''&&!$config['sms']['enabled']);
    unlink($path);
    $config=bm_integration_config();
    verify_config('Missing integration configuration leaves the application with disabled defaults',!$config['identity']['enabled']&&!$config['sms']['enabled']&&!$config['whatsapp']['enabled']);
    echo "PASS $checks private configuration checks; no network or live data.".PHP_EOL;
} finally { if(is_file($path))unlink($path);putenv('BULKMAIL_INTEGRATIONS_CONFIG'); }
