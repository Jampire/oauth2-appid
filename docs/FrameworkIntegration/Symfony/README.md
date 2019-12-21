# Symfony Framework Integration

This documentation is for generic type provider. As soon as IBM App ID provider will be included into [knpuniversity/oauth2-client-bundle](https://github.com/knpuniversity/oauth2-client-bundle
), this documentation will be updated. 

Full documentation for adding providers is available at [KnpUOAuth2ClientBundle](https://github.com/knpuniversity/oauth2-client-bundle).
This example is based on [Symfony v4.3](https://symfony.com).

### Step 1 - Configuring Security

Configure your oauth security.

```yaml
# config/packages/security.yaml
security:
    providers:
        oauth:
            id: App\Security\UserProvider
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            guard:
                authenticators:
                    - App\Security\AppIdAuthenticator
```

```yaml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
    clients:
        appid:
            type: generic
            provider_class: Jampire\OAuth2\Client\Provider\AppIdProvider

            # optional: a class that extends OAuth2Client
            client_class: App\Security\AppIdClient

            provider_options: {baseAuthUri: '%env(OAUTH_APPID_BASE_AUTH_URI)%',tenantId: '%env(OAUTH_APPID_TENANT_ID)%',idp: '%env(OAUTH_APPID_IDP)%',redirectRoute: '%env(OAUTH_APPID_REDIRECT_ROUTE)%'}

            # now, all the normal options!
            client_id: '%env(OAUTH_APPID_CLIENT_ID)%'
            client_secret: '%env(OAUTH_APPID_CLIENT_SECRET)%'
            redirect_route: '%env(OAUTH_APPID_REDIRECT_ROUTE)%'
            redirect_params: {}
```

Add your credentials in env
```dotenv
OAUTH_APPID_BASE_AUTH_URI=https://xxx.appid.cloud.ibm.com/oauth/v4
OAUTH_APPID_REDIRECT_ROUTE=connect_appid_check
OAUTH_APPID_IDP=saml
OAUTH_APPID_TENANT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
OAUTH_APPID_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
OAUTH_APPID_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxx
```

### Step 2 - Add the client controller

Create IBM App ID authenticator controller

```php
<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Class AppIdController
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Controller
 */
class AppIdController extends AbstractController
{
    /**
     * @Route("/connect", name="connect_appid")
     *
     * Authorization route
     *
     * @param ClientRegistry $clientRegistry
     *
     * @return RedirectResponse
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function connect(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry->getClient('appid')->redirect();
    }

    /**
     * @Route("/connect/check", name="connect_appid_check")
     *
     * Callback route
     *
     * @return Response
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function check(): Response
    {
        if (!$this->getUser()) {
            return new JsonResponse([
                'status' => false,
                'message' => 'User not found!',
            ]);
        }

        return $this->redirectToRoute('home');
    }
}
```

Create HomeController

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Class HomeController
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Controller
 */
class HomeController extends AbstractController
{
    /**
     * @Route("/", name="home")
     * @return JsonResponse
     * @author  Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function home(): JsonResponse
    {
        $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');

        return new JsonResponse([
            'name' => $this->getUser()->getFullName(),
            'email' => $this->getUser()->getEmail(),
        ]);
    }
}

```

### Step 3 - Add the guard authenticator

Create IBM App ID authenticator guard. Below code block is published under MIT license. Please see [License File](https://github.com/Jampire/oauth2-appid/blob/master/LICENSE) for more information.

```php
<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class AppIdAuthenticator
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Security
 */
class AppIdAuthenticator extends SocialAuthenticator
{
    /** @var ClientRegistry  */
    private $clientRegistry;

    /** @var RouterInterface */
    private $router;

    public function __construct(ClientRegistry $clientRegistry, RouterInterface $router)
    {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
    }

    /**
     * @param Request $request
     *
     * @return bool
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function supports(Request $request): bool
    {
        $provider = $this->getClient()->getOAuth2Provider();

        return ($request->isMethod('GET') &&
                $request->getPathInfo() === $this->router->generate($provider->getRedirectRoute()));
    }

    /**
     * @param Request $request
     *
     * @return AccessToken|mixed
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getCredentials(Request $request): AccessToken
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param mixed                 $credentials
     * @param UserProviderInterface|UserProvider $userProvider
     *
     * @return UserInterface
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getUser($credentials, UserProviderInterface $userProvider): UserInterface
    {
        return $userProvider->loadUserByUsername($this->getClient()->fetchUserFromToken($credentials));
    }

    /**
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function checkCredentials($credentials, UserInterface $user): bool
    {
        $provider = $this->getClient()->getOAuth2Provider();

        return $provider->validateAccessToken($credentials);
    }

    /**
     * @return OAuth2ClientInterface|AppIdClient
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    private function getClient(): OAuth2ClientInterface
    {
        return $this->clientRegistry->getClient('appid');
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return Response|null
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        // let the request continue to be handled by the controller
        return null;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent.
     * This redirects to the App ID authorization.
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     *
     * @return RedirectResponse
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        return $this->getClient()->redirect();
    }
}
```

```php
<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Client\OAuth2Client;

/**
 * Class AppIdClient
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Security
 */
class AppIdClient extends OAuth2Client
{

}
```

### Step 4 - Add User security

Full documentation for adding providers is available at [Symfony Security Documentation](https://symfony.com/doc/current/security.html). 

Create User provider class. Below code block is published under MIT license. Please see [License File](https://github.com/Jampire/oauth2-appid/blob/master/LICENSE) for more information.

```php
<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Security\User\OAuthUserProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use function get_class;

/**
 * Class UserProvider
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Security
 */
class UserProvider extends OAuthUserProvider
{
    private $roles;

    public function __construct(array $roles = ['ROLE_USER', 'ROLE_OAUTH_USER'])
    {
        $this->roles = $roles;
        parent::__construct($roles);
    }

    /**
     * @param ResourceOwnerInterface $resourceOwner
     *
     * @return UserInterface
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function loadUserByUsername($resourceOwner): UserInterface
    {
        return new User($resourceOwner, $this->roles);
    }

    public function supportsClass($class): bool
    {
        return User::class === $class;
    }

    /**
     * @param UserInterface $user
     *
     * @return UserInterface
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getResourceOwner());
    }
}
```

Create User class. Below code block is published under MIT license. Please see [License File](https://github.com/Jampire/oauth2-appid/blob/master/LICENSE) for more information.

```php
<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Security\User\OAuthUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Class User
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package App\Security
 */
class User extends OAuthUser
{
    /** @var string */
    private $fullName;

    /** @var string */
    private $cNum;

    /** @var string */
    private $lotusNotesId;

    /** @var array */
    private $ibmInfo = [];

    /** @var string */
    private $location;

    /** @var ResourceOwnerInterface  */
    private $resourceOwner;

    /**
     * User constructor.
     *
     * @param array $roles
     * @param ResourceOwnerInterface $resourceOwner
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function __construct(ResourceOwnerInterface $resourceOwner, array $roles)
    {
        $this->resourceOwner = $resourceOwner;
        $this->setFullName($this->resourceOwner->getFullName());
        $this->setCnum($this->resourceOwner->getCnum());
        $this->setLotusNotesId($this->resourceOwner->getLotusNotesId());
        $this->setIbmInfo($this->resourceOwner->getIbmInfo());
        $this->setLocation($this->resourceOwner->getLocation());

        parent::__construct($resourceOwner->getEmail(), $roles);
    }

    /**
     * @return string|null
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getEmail(): ?string
    {
        return $this->getUsername();
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getFullName(): ?string
    {
        return $this->fullName;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @param string $fullName
     *
     * @return self
     */
    public function setFullName(string $fullName): self
    {
        $this->fullName = $fullName;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getCnum(): ?string
    {
        return $this->cNum;
    }

    /**
     * @param string $cNum
     *
     * @return self
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function setCnum(string $cNum): self
    {
        $this->cNum = $cNum;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getLotusNotesId(): ?string
    {
        return $this->lotusNotesId;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @param string $lotusNotesId
     *
     * @return self
     */
    public function setLotusNotesId(string $lotusNotesId): self
    {
        $this->lotusNotesId = $lotusNotesId;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return array
     */
    public function getIbmInfo(): array
    {
        return $this->ibmInfo;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @param array $ibmInfo
     *
     * @return self
     */
    public function setIbmInfo(array $ibmInfo = []): self
    {
        $this->ibmInfo = $ibmInfo;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getLocation(): ?string
    {
        return $this->location;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @param string $location
     *
     * @return self
     */
    public function setLocation(string $location): self
    {
        $this->location = $location;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }
}
```
