<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Jampire\OAuth2\Client\Provider\AppIdProvider;
use Jampire\OAuth2\Client\Provider\AppIdException;

session_start();

try {
    $provider = new AppIdProvider([
        'base_auth_uri' => '',
        'tenant_id'     => '',
        'clientId'      => '',
        'clientSecret'  => '',
        'redirectUri'   => '',
    ]);
} catch (AppIdException $e) {
    exit('Failed to create provider: ' . $e->getMessage());
}

try {
    // Try to get an access token using the resource owner password credentials grant.
    $accessToken = $provider->getAccessToken('password', [
        'username' => 'demouser',
        'password' => 'testpass',
    ]);

} catch (Exception $e) {
    // Failed to get the access token
    exit($e->getMessage());
}
