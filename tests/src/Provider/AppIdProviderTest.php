<?php

namespace Jampire\OAuth2\Client\Test\Provider;

use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\ClientInterface;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Mockery as m;
use Jampire\OAuth2\Client\Provider\AppIdProvider;
use Jampire\OAuth2\Client\Provider\AppIdException;

/**
 * Class AppIdProviderTest
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>>
 * @package Jampire\OAuth2\Client\Test\Provider
 */
class AppIdProviderTest extends MockeryTestCase
{
    /** @var AppIdProvider */
    protected $provider;

    /** @var string */
    protected $baseAuthUri = 'mock_base_auth_uri';

    /** @var string */
    protected $tenantId = 'mock_tenant_id';

    /** @var string */
    protected $redirectRoute = 'mock_redirect_route';

    /** @var string */
    protected $clientId = 'mock_client_id';

    /** @var string */
    protected $clientSecret = 'mock_client_secret';

    /** @var string */
    protected $redirectUri = 'mock_redirect_uri';

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function setUp(): void
    {
        $this->provider = new AppIdProvider([
            'base_auth_uri' => $this->baseAuthUri,
            'tenant_id' => $this->tenantId,
            'redirect_route' => $this->redirectRoute,
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
            'redirectUri' => $this->redirectUri,
        ]);
    }

    public function testAuthorizationUrl(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertArrayHasKey('idp', $query);
        $this->assertNotNull($this->provider->getState());
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetAuthorizationUrl(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri . '/' . $this->tenantId . '/authorization', $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetBaseAuthUri(): void
    {
        $url = $this->provider->getBaseAuthUri();
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri, $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetTenantId(): void
    {
        $this->assertEquals($this->tenantId, $this->provider->getTenantId());
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetBaseAccessTokenUrl(): void
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri . '/' . $this->tenantId . '/token', $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetResourceOwnerDetailsUrl(): void
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getHeader')
                 ->times(1)
                 ->andReturn('application/json');
        $data = [
            'access_token' => 'mock_access_token',
            'id_token' => 'mock_id_token',
            'refresh_token' => 'mock_refresh_token',
            'token_type' => 'bearer',
            'expires_in' => 3600,
        ];
        $response->shouldReceive('getBody')
                 ->times(1)
                 ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $url = $this->provider->getResourceOwnerDetailsUrl($token);
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri . '/' . $this->tenantId . '/userinfo', $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetIntrospectUrl(): void
    {
        $url = $this->provider->getIntrospectUrl();
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri . '/' . $this->tenantId . '/introspect', $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetRevokeUrl(): void
    {
        $url = $this->provider->getRevokeUrl();
        $uri = parse_url($url);

        $this->assertEquals($this->baseAuthUri . '/' . $this->tenantId . '/revoke', $uri['path']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetRedirectRouteName(): void
    {
        $this->assertEquals($this->redirectRoute, $this->provider->getRedirectRouteName());
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetIdp(): void
    {
        $this->assertEquals('saml', $this->provider->getIdp());
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testDefaultScope(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertEquals('openid', $query['scope']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testGetAccessToken(): void
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getHeader')
                 ->times(1)
                 ->andReturn('application/json');
        $data = [
            'access_token' => 'mock_access_token',
            'id_token' => 'mock_id_token',
            'refresh_token' => 'mock_refresh_token',
            'token_type' => 'bearer',
            'expires_in' => 3600,
        ];
        $response->shouldReceive('getBody')
                 ->times(1)
                 ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertEquals('mock_id_token', $token->getValues()['id_token']);
        $this->assertEquals('mock_refresh_token', $token->getRefreshToken());
        $this->assertEquals('bearer', $token->getValues()['token_type']);
        $this->assertLessThanOrEqual(time() + 3600, $token->getExpires());
        $this->assertGreaterThanOrEqual(time(), $token->getExpires());
        $this->assertNull($token->getResourceOwnerId());
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testErrorResponse(): void
    {
        $this->expectException(IdentityProviderException::class);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getHeader')
                 ->times(1)
                 ->andReturn('application/json');
        $data = [
            'error' => 'invalid_grant',
            'error_description' => 'Code not found',
        ];
        $response->shouldReceive('getBody')
                 ->times(1)
                 ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testResourceOwner(): void
    {
        $userId = 1;
        $name = 'Dzianis Kotau';
        $email = 'jampire.blr@gmail.com';
        $cNum = 'xxx-001';
        $lotusNotesId = 'CN=Dzianis Kotau/OU=Org1/OU=Org2/O=IBM@IBMMail';
        $location = 'BY';

        $postResponse = m::mock(ResponseInterface::class);
        $postResponse->shouldReceive('getHeader')
                 ->times(1)
                 ->andReturn('application/json');
        $data = [
            'access_token' => 'mock_access_token',
            'id_token' => 'mock_id_token',
            'refresh_token' => 'mock_refresh_token',
            'token_type' => 'bearer',
            'expires_in' => 3600,
        ];
        $postResponse->shouldReceive('getBody')
                 ->times(1)
                 ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $data = [
            'sub' => $userId,
            'name' => $name,
            'email' => $email,
            'identities' => [
                [
                    'idpUserInfo' => [
                        'attributes' => [
                            'cnum' => $cNum,
                            'lotusnotesid' => $lotusNotesId,
                            'ibminfo' => [],
                            'locate' => $location,
                            'uid' => $userId,
                        ],
                    ],
                ],

            ],
        ];

        $userResponse = m::mock(ResponseInterface::class);
        $userResponse->shouldReceive('getHeader')
                     ->times(1)
                     ->andReturn('application/json');
        $userResponse->shouldReceive('getBody')
                     ->times(1)
                     ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
               ->times(2)
               ->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        /** @var \Jampire\OAuth2\Client\Provider\AppIdResourceOwner $user */
        $user = $this->provider->getResourceOwner($token);
        $attributes = $user->toArray()['identities'][0]['idpUserInfo']['attributes'];

        $this->assertEquals($userId, $user->getId());
        $this->assertEquals($userId, $user->toArray()['sub']);

        $this->assertEquals($name, $user->getFullName());
        $this->assertEquals($name, $user->toArray()['name']);

        $this->assertEquals($email, $user->getEmail());
        $this->assertEquals($email, $user->toArray()['email']);

        $this->assertEquals($cNum, $user->getCnum());
        $this->assertEquals($cNum, $attributes['cnum']);

        $this->assertEquals('Dzianis Kotau/Org1/Org2/IBM', $user->getLotusNotesId());
        $this->assertEquals($lotusNotesId, $attributes['lotusnotesid']);

        $this->assertEquals([], $user->getIbmInfo());
        $this->assertEquals([], $attributes['ibminfo']);

        $this->assertEquals($location, $user->getLocation());
        $this->assertEquals($location, $attributes['locate']);

        $this->assertEquals($userId, $user->getUid());
        $this->assertEquals($userId, $attributes['uid']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testValidateAccessToken(): void
    {
        $postResponse = m::mock(ResponseInterface::class);
        $postResponse->shouldReceive('getHeader')
                     ->times(1)
                     ->andReturn('application/json');
        $data = [
            'access_token' => 'mock_access_token',
            'id_token' => 'mock_id_token',
            'refresh_token' => 'mock_refresh_token',
            'token_type' => 'bearer',
            'expires_in' => 3600,
        ];
        $postResponse->shouldReceive('getBody')
                     ->times(1)
                     ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $validateResponse = m::mock(ResponseInterface::class);
        $validateResponse->shouldReceive('getHeader')
                         ->times(1)
                         ->andReturn('application/json');
        $data = [
            'active' => true,
        ];
        $validateResponse->shouldReceive('getBody')
                         ->times(1)
                         ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
               ->times(2)
               ->andReturn($postResponse, $validateResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $valid = $this->provider->validateAccessToken($token);

        $this->assertTrue($valid);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testRevokeRefreshToken(): void
    {
        $postResponse = m::mock(ResponseInterface::class);
        $postResponse->shouldReceive('getHeader')
                     ->times(1)
                     ->andReturn('application/json');
        $data = [
            'access_token' => 'mock_access_token',
            'id_token' => 'mock_id_token',
            'refresh_token' => 'mock_refresh_token',
            'token_type' => 'bearer',
            'expires_in' => 3600,
        ];
        $postResponse->shouldReceive('getBody')
                     ->times(1)
                     ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $validateResponse = m::mock(ResponseInterface::class);
        $validateResponse->shouldReceive('getHeader')
                         ->times(1)
                         ->andReturn('application/json');
        $data = 'OK';
        $validateResponse->shouldReceive('getBody')
                         ->times(1)
                         ->andReturn(json_encode($data, JSON_THROW_ON_ERROR, 512));

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
               ->times(2)
               ->andReturn($postResponse, $validateResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $revoked = $this->provider->revokeRefreshToken($token);

        $this->assertTrue($revoked);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testDefaultIdp(): void
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertEquals(AppIdProvider::IDP_SAML, $query['idp']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testAllowedIdp(): void
    {
        $url = $this->provider->getAuthorizationUrl(['idp' => AppIdProvider::IDP_GOOGLE]);
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertEquals(AppIdProvider::IDP_GOOGLE, $query['idp']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testDisallowedIdp(): void
    {
        $this->expectException(AppIdException::class);
        $this->expectExceptionMessage('IDP "not_allowed" is not supported.');
        $this->provider->getAuthorizationUrl(['idp' => 'not_allowed']);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function testErrorInitialization(): void
    {
        $this->expectException(AppIdException::class);
        $this->expectExceptionMessage('Required fields (base_auth_uri or tenant_id) are missing.');
        $provider = new AppIdProvider([
            'redirect_route' => $this->redirectRoute,
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
            'redirectUri' => $this->redirectUri,
        ]);
    }
}
