<?php
declare(strict_types=1);

// Pure validation and injected transport only: no DNS, network or real credentials.
require dirname(__DIR__).'/app/bulkmail-identity.php';
$checks=0;
function route_check(string $name, bool $ok): void {
    global $checks;
    if (!$ok) throw new RuntimeException('FAIL '.$name);
    $checks++; echo 'PASS '.$name.PHP_EOL;
}
$cfg=['enabled'=>true,'base_url'=>'https://workspace.example.invalid','allow_http'=>false];
$issuer=bm_identity_issuer($cfg);
route_check('An omitted route preserves ordinary DNS',bm_identity_resolve_rule($cfg,$issuer)===null);
route_check('An empty route preserves ordinary DNS',bm_identity_resolve_rule($cfg+['connect_address'=>''],$issuer)===null);
route_check('IPv4 pin binds only the original hostname and HTTPS port',
    bm_identity_resolve_rule($cfg+['connect_address'=>'192.0.2.7'],$issuer)==='workspace.example.invalid:443:192.0.2.7');
route_check('A non-default issuer port is retained exactly',
    bm_identity_resolve_rule($cfg+['connect_address'=>'127.0.0.1'],'https://workspace.example.invalid:8443')==='workspace.example.invalid:8443:127.0.0.1');
route_check('IPv6 destination uses the required rule brackets',
    bm_identity_resolve_rule($cfg+['connect_address'=>'2001:db8::7'],$issuer)==='workspace.example.invalid:443:[2001:db8::7]');
route_check('An IPv4 URL hostname remains supported',
    bm_identity_resolve_rule($cfg+['connect_address'=>'127.0.0.1'],'https://192.0.2.4:9443')==='192.0.2.4:9443:127.0.0.1');
$calls=0;
$transport=static function()use(&$calls):array { $calls++; return ['fixture'=>true]; };
foreach ([null,false,0,[],(object)[], 'localhost','127.0.0.1:443','127.0.0.1,192.0.2.1',
    ' 127.0.0.1','127.0.0.1 ',"127.0.0.1\nHost: private",'[::1]','fe80::1%lo','192.168.001.1','127.0.0.1/8'] as $i=>$bad) {
    try {
        bm_identity_request(array_replace($cfg,['connect_address'=>$bad]),'GET','/api/2.0/people/@self.json',null,'fixture',$transport);
        route_check('Invalid route '.$i.' is rejected before transport',false);
    } catch (BMIdentityException $e) {
        route_check('Invalid route '.$i.' is rejected before transport',$e->reason==='request_invalid'&&$calls===0);
    }
}
foreach (['https://*.example.invalid','https://one.invalid,two.invalid','https://[::1]',
    'http://workspace.example.invalid','https://workspace.example.invalid:0'] as $i=>$badIssuer) {
    try {
        bm_identity_resolve_rule($cfg+['connect_address'=>'127.0.0.1'],$badIssuer);
        route_check('Invalid pin issuer '.$i.' is rejected',false);
    } catch (BMIdentityException $e) {
        route_check('Invalid pin issuer '.$i.' is rejected',$e->reason==='request_invalid');
    }
}
$_GET=['connect_address'=>'192.0.2.9'];$_POST=$_GET;$_COOKIE=$_GET;
$_SERVER=['HTTP_X_CONNECT_ADDRESS'=>'192.0.2.9'];
route_check('Request claims cannot enable an unconfigured route',bm_identity_resolve_rule($cfg,$issuer)===null);
route_check('Request claims cannot replace the configured route',
    bm_identity_resolve_rule($cfg+['connect_address'=>'127.0.0.1'],$issuer)==='workspace.example.invalid:443:127.0.0.1');
route_check('A pin does not change the identity issuer',bm_identity_issuer($cfg+['connect_address'=>'127.0.0.1'])===$issuer);
route_check('Unpinned injected transport remains unchanged',
    bm_identity_request($cfg,'GET','/api/2.0/people/@self.json',null,'fixture',$transport)===['fixture'=>true]&&$calls===1);
echo 'PASS '.$checks.' private-route validation checks; no network.'.PHP_EOL;
