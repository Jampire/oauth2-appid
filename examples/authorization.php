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

if (!isset($_GET['code'])) {
    // If we don't have an authorization code then get one

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;
}

if (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    // Check given state against previously stored one to mitigate CSRF attack
    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }
    exit('Invalid state');

}

try {
    // Try to get an access token using the authorization code grant.
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // We have an access token, which we may use in authenticated
    // requests against the service provider's API.
    echo '<b>Access Token:</b> ', $accessToken->getToken() , '<br>';
    echo '<b>Refresh Token:</b> ' , $accessToken->getRefreshToken() , '<br>';
    echo '<b>Expired in:</b> ' , $accessToken->getExpires() , '<br>';
    echo '<b>Already expired?</b> ' , ($accessToken->hasExpired() ? 'expired' : 'not expired') , '<br>';

    // Using the access token, we may look up details about the
    // resource owner.
    $resourceOwner = $provider->getResourceOwner($accessToken);
    echo '<pre>';
    var_export($resourceOwner->toArray());
    echo '</pre>';
} catch (Exception $e) {
    // Failed to get the access token or user details.
    exit($e->getMessage());
}
