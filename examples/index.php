<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Jampire\OAuth2\Client\Provider\AppIdProvider;
use Jampire\OAuth2\Client\Provider\AppIdResourceOwner;
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

if (!isset($_GET['code'])) {
    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: ' . $authUrl);
    exit;
}

if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
    // Check given state against previously stored one to mitigate CSRF attack
    unset($_SESSION['oauth2state']);
    exit('Invalid state, make sure HTTP sessions are enabled.');
}

// Try to get an access token (using the authorization code grant)
try {
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code'],
    ]);
} catch (Exception $e) {
    exit('Failed to get access token: ' . $e->getMessage());
}

// Optional: Now you have a token, you can look up a users profile data
try {
    // We got an access token, let's now get the user's details
    /** @var AppIdResourceOwner $user */
    $user = $provider->getResourceOwner($token);
    // Use these details to create a new profile
    printf('Hello %s!\n<br>', $user->getFullName());
} catch (Exception $e) {
    exit('Failed to get resource owner: ' . $e->getMessage());
}

// Use this to interact with an API on the users behalf
echo $token->getToken();
