<?php

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/src/keychain.php';
$options = [
    'json' => __DIR__.'/key.json',
];
$keyChain = new recca0120\ios\KeyChain($options);
$keyChain->createCertSigningRequest(__DIR__.'/test/');
$developement = __DIR__.'/test/aps_development.cer';
$production = __DIR__.'/test/aps_production.cer';
if (file_exists($developement) === true) {
    $keyChain->loadCer(file_get_contents($developement), '');
    $filename = $keyChain->save($keyChain->generate(), __DIR__.'/test/');
    file_put_contents($filename.'.base64', base64_encode(file_get_contents($filename)));
}
if (file_exists($production) === true) {
    $keyChain->loadCer(file_get_contents($production), '');
    $filename = $keyChain->save($keyChain->generate(), __DIR__.'/test/');
    file_put_contents($filename.'.base64', base64_encode(file_get_contents($filename)));
}

// foreach (glob(__DIR__.'/test/*.pem') as $filename) {
//     file_put_contents($filename.'.base64', base64_encode(file_get_contents($filename)));
// }
