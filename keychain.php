<?php

require __DIR__.'/vendor/autoload.php';
require __DIR__.'/src/keychain.php';

$keyChain = new recca0120\ios\KeyChain();
$keyChain->createCertSigningRequest(__DIR__.'/test/');
if (file_exists(__DIR__.'/test/aps_development.cer') === true) {
    $keyChain->loadCer(file_get_contents(__DIR__.'/test/aps_development.cer'), '');
    $keyChain->save($keyChain->generate(), __DIR__.'/test/');
}
if (file_exists(__DIR__.'/test/aps_production.cer') === true) {
    $keyChain->loadCer(file_get_contents(__DIR__.'/test/aps_production.cer'), '');
    $keyChain->save($keyChain->generate(), __DIR__.'/test/');
}