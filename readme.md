# IBM App ID Provider for OAuth 2.0 Client

[![Build Status](https://travis-ci.org/Jampire/oauth2-appid.svg?branch=master)](https://travis-ci.org/Jampire/oauth2-appid)
[![Scrutinizer coverage (GitHub/BitBucket)](https://img.shields.io/scrutinizer/coverage/g/Jampire/oauth2-appid?style=flat-square)](https://scrutinizer-ci.com/g/Jampire/oauth2-appid/code-structure/master)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/jampire/oauth2-appid?style=flat-square)](https://github.com/Jampire/oauth2-appid/releases)
[![PHP from Packagist](https://img.shields.io/packagist/php-v/Jampire/oauth2-appid?style=flat-square)](https://packagist.org/packages/jampire/oauth2-appid)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Jampire/oauth2-appid/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Jampire/oauth2-appid/?branch=master)
[![Code Intelligence Status](https://scrutinizer-ci.com/g/Jampire/oauth2-appid/badges/code-intelligence.svg?b=master)](https://scrutinizer-ci.com/code-intelligence)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/Jampire/oauth2-appid?sort=semver&style=flat-square)](https://github.com/Jampire/oauth2-appid/releases)
[![GitHub](https://img.shields.io/github/license/Jampire/oauth2-appid?style=flat-square)](LICENSE)
[![Packagist](https://img.shields.io/packagist/dt/Jampire/oauth2-appid?style=flat-square)](https://packagist.org/packages/jampire/oauth2-appid)
[![GitHub contributors](https://img.shields.io/github/contributors/Jampire/oauth2-appid?style=flat-square)](https://github.com/Jampire/oauth2-appid/graphs/contributors)
[![GitHub last commit](https://img.shields.io/github/last-commit/Jampire/oauth2-appid?style=flat-square)](https://github.com/Jampire/oauth2-appid/commits/master)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat-square)](https://github.com/Jampire/oauth2-appid/issues)

This package provides [IBM App ID](https://cloud.ibm.com/catalog/services/app-id#about) OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require jampire/oauth2-appid
```

## Usage

Usage is the same as The League's OAuth client, using `\Jampire\OAuth2\Client\Provider\AppIdProvider` as the provider.

Use `baseAuthUri` to specify the IBM App ID base server URL. You can lookup the correct value from the Application settings of your IBM App ID service under `oAuthServerUrl` without `tenantId` section, eg. `https://us-south.appid.cloud.ibm.com/oauth/v4`.

Use `tenantId` to specify the IBM App ID tenant ID. You can lookup the correct value from the Application settings of your IBM App ID service under `tenantId`, eg. `abcd-efgh-1234-5678-mnop`.

All other values you can find in Application settings of your IBM App ID service.

Do not forget to register your redirect URL in your IBM App ID whitelist. Please, read IBM App ID [documentation](https://cloud.ibm.com/docs/services/appid?topic=appid-getting-started).

### Authorization Code Flow

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Jampire\OAuth2\Client\Provider\AppIdProvider;
use Jampire\OAuth2\Client\Provider\AppIdException;

session_start();

try {
    $provider = new AppIdProvider([
        'baseAuthUri'   => '{baseAuthUri}',
        'tenantId'      => '{tenantId}',
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
    echo '<b>Access Token:</b> ', $accessToken->getToken(), '<br>';
    echo '<b>Refresh Token:</b> ', $accessToken->getRefreshToken(), '<br>';
    echo '<b>Expired in:</b> ', $accessToken->getExpires(), '<br>';
    echo '<b>Already expired?</b> ', ($accessToken->hasExpired() ? 'expired' : 'not expired'), '<br>';

    // Using the access token, we may look up details about the
    // resource owner.
    $resourceOwner = $provider->getResourceOwner($accessToken);
} catch (Exception $e) {
    // Failed to get the access token or user details.
    exit($e->getMessage());
}

```

## Examples
- [Code examples](docs/examples).
- [Symfony Integration example](docs/FrameworkIntegration/Symfony).

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
