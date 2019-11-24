<?php

namespace Jampire\OAuth2\Client\Provider;

use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use UnexpectedValueException;

/**
 * Class AppIdProvider
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package Jampire\OAuth2\Client\Provider
 */
class AppIdProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public const IDP_SAML = 'saml';
    public const IDP_ANON = 'appid_anon';
    public const IDP_FACEBOOK = 'facebook';
    public const IDP_GOOGLE = 'google';

    /** @var string */
    private $baseAuthUri;

    /** @var string */
    private $tenantId;

    /** @var string */
    private $redirectRouteName;

    /** @var string */
    private $idp;

    /**
     * AppIdProvider constructor.
     *
     * @inheritDoc
     *
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @throws AppIdException
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (!isset($options['base_auth_uri'], $options['tenant_id'])) {
            throw new AppIdException('Required fields (base_auth_uri or tenant_id) are missing.');
        }

        $this->setBaseAuthUri($options['base_auth_uri']);
        $this->setTenantId($options['tenant_id']);

        if (isset($options['redirect_route'])) {
            $this->setRedirectRouteName($options['redirect_route']);
        }

        $idp = empty($options['idp']) ? self::IDP_SAML : $options['idp'];
        $this->setIdp($idp);

        unset($options['base_auth_uri'], $options['tenant_id'], $options['redirect_route'], $options['idp'], $idp);

        $collaborators['optionProvider'] = new HttpBasicAuthOptionProvider();

        parent::__construct($options, $collaborators);
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getBaseAuthUri() . '/' . $this->getTenantId() . '/authorization';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getBaseAuthUri() . '/' . $this->getTenantId() . '/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getBaseAuthUri() . '/' . $this->getTenantId() . '/userinfo';
    }

    /**
     * Returns the URL for introspecting and validating App ID tokens.
     *
     * @return string
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getIntrospectUrl(): string
    {
        return $this->getBaseAuthUri() . '/' . $this->getTenantId() . '/introspect';
    }

    /**
     * Returns the URL for revoking App ID tokens.
     *
     * @return string
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getRevokeUrl(): string
    {
        return $this->getBaseAuthUri() . '/' . $this->getTenantId() . '/revoke';
    }

    /**
     * Introspects and validates App ID token.
     *
     * @param AccessToken $token
     *
     * @return bool
     * @throws IdentityProviderException
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function validateAccessToken(AccessToken $token): bool
    {
        $body = $this->fetchIntrospect($token);

        return is_array($body) && !empty($body['active']);
    }

    /**
     * Revokes refresh token.
     *
     * @param AccessToken $token
     *
     * @throws IdentityProviderException
     * @return bool True if revoke was successful, false otherwise
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function revokeRefreshToken(AccessToken $token): bool
    {
        $body = $this->fetchRevoke($token);

        return $body === 'OK';
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getBaseAuthUri(): string
    {
        return $this->baseAuthUri;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getTenantId(): string
    {
        return $this->tenantId;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getRedirectRouteName(): string
    {
        return $this->redirectRouteName;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getIdp(): string
    {
        return $this->idp;
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes(): array
    {
        return ['openid'];
    }

    /**
     * Checks a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param array|string      $data Parsed response data
     *
     * @return void
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            $error = $data['error'] . ': ' . $data['error_description'];
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param array       $response
     * @param AccessToken $token
     *
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface
    {
        return new AppIdResourceOwner($response);
    }

    /**
     * Requests introspect details.
     *
     * @param AccessToken $token
     *
     * @return array Introspect details ['active' => true/false]
     * @throws IdentityProviderException
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    protected function fetchIntrospect(AccessToken $token): array
    {
        $url = $this->getIntrospectUrl();
        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'token'         => $token->getToken(),
        ];
        $options = $this->optionProvider->getAccessTokenOptions(self::METHOD_POST, $params);
        $request = $this->getRequest(self::METHOD_POST, $url, $options);
        $response = $this->getParsedResponse($request);

        if (is_array($response) === false) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON. Got: ' . $response
            );
        }

        return $response;
    }

    /**
     * @param AccessToken $token
     *
     * @return string 'OK' if revoke was successful
     * @throws IdentityProviderException
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    protected function fetchRevoke(AccessToken $token): string
    {
        $url = $this->getRevokeUrl();
        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'token'         => $token->getToken(),
        ];
        $options = $this->optionProvider->getAccessTokenOptions(self::METHOD_POST, $params);
        $request = $this->getRequest(self::METHOD_POST, $url, $options);
        $response = $this->getParsedResponse($request);

        if (is_string($response) === false) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected "OK". Got: ' . $response
            );
        }

        return $response;
    }

    /**
     * @inheritDoc
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    protected function getAuthorizationParameters(array $options): array
    {
        if (empty($options['idp'])) {
            $options['idp'] = $this->getIdp();
        }

        return parent::getAuthorizationParameters($options);
    }

    /**
     * @param string $baseUri
     *
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return self
     */
    private function setBaseAuthUri(string $baseUri): self
    {
        $this->baseAuthUri = $baseUri;

        return $this;
    }

    /**
     * @param string $tenantId
     *
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return self
     */
    private function setTenantId(string $tenantId): self
    {
        $this->tenantId = $tenantId;

        return $this;
    }

    /**
     * @param string $redirectRouteName
     *
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return self
     */
    private function setRedirectRouteName(string $redirectRouteName): self
    {
        $this->redirectRouteName = $redirectRouteName;

        return $this;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @param string $idp
     *
     * @throws AppIdException
     * @return self
     */
    private function setIdp(string $idp): self
    {
        if (!in_array($idp, [
            self::IDP_SAML,
            self::IDP_ANON,
            self::IDP_FACEBOOK,
            self::IDP_GOOGLE,
        ], true)) {
            throw new AppIdException('IDP "' . $idp . '" is not supported.');
        }

        $this->idp = $idp;

        return $this;
    }
}
