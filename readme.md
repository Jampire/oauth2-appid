# IBM App ID Provider for OAuth 2.0 Client

This package provides [IBM App ID](https://cloud.ibm.com/catalog/services/app-id#about) OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require jampire/oauth2-appid
```

## Usage

Usage is the same as The League's OAuth client, using `\Jampire\OAuth2\Client\Provider\AppIdProvider` as the provider.

Use `base_auth_uri` to specify the IBM App ID base server URL. You can lookup the correct value from the Application settings of your IBM App ID service under `oAuthServerUrl` without `tenantId` section, eg. `https://us-south.appid.cloud.ibm.com/oauth/v4`.

Use `tenant_id` to specify the IBM App ID tenant ID. You can lookup the correct value from the Application settings of your IBM App ID service under `tenantId`, eg. `abc-zyz-123`.

All other values you can find in Application settings of your IBM App ID service under.

### Authorization Code Flow

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Jampire\OAuth2\Client\Provider\AppIdProvider;
use Jampire\OAuth2\Client\Provider\AppIdException;

session_start();

try {
    $provider = new AppIdProvider([
        'base_auth_uri' => '{base_auth_uri}',
        'tenant_id'     => '{tenant_id}',
        'clientId'      => '{clientId}',
        'clientSecret'  => '{clientSecret}',
        'redirectUri'   => '{redirectUri}',
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
} catch (Exception $e) {
    // Failed to get the access token or user details.
    exit($e->getMessage());
}

```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/Jampire/oauth2-appid/blob/master/CONTRIBUTING.md) for details.


## Credits

- [Dzianis Kotau](https://github.com/Jampire)
- [All Contributors](https://github.com/Jampire/oauth2-appid/graphs/contributors)


## License

The MIT License (MIT). Please see [License File](https://github.com/Jampire/oauth2-appid/blob/master/LICENSE) for more information.
