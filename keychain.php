<?php

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/src/keychain.php';
$options = [
    'json' => __DIR__.'/rsa.json',
];
$keyChain = new recca0120\ios\KeyChain($options);
$keyChain->createCertSigningRequest(__DIR__.'/test/');
if (file_exists(__DIR__.'/test/aps_development.cer') === true) {
    $keyChain->loadCer(file_get_contents(__DIR__.'/test/aps_development.cer'), '');
    $keyChain->save($keyChain->generate(), __DIR__.'/test/');
}
if (file_exists(__DIR__.'/test/aps_production.cer') === true) {
    $keyChain->loadCer(file_get_contents(__DIR__.'/test/aps_production.cer'), '');
    $keyChain->save($keyChain->generate(), __DIR__.'/test/');
}
