<?php

namespace Jampire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Class AppIdResourceOwner
 *
 * Individual resource owners may introduce more attributes, as needed.
 *
 * @author  Dzianis Kotau <jampire.blr@gmail.com>
 * @package Jampire\OAuth2\Client\Provider
 */
class AppIdResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /** @var array */
    protected $attributes = [];

    /**
     * Creates new resource owner.
     *
     * @param array $response
     */
    public function __construct(array $response = [])
    {
        $this->response = $response;
        $this->attributes = $this->getAttributes();
    }

    /**
     * Parsed canonical Lotus Notes Id to human one.
     *
     * For example
     * "CN=Dzianis Kotau/OU=Org1/OU=Org2/O=IBM@IBMMail" is parsed to
     * "Dzianis Kotau/Org1/Org2/IBM"
     *
     * @param string $lotusNotesId Canonical Lotus Notes Id
     *
     * @return string Human Lotus Notes Id
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public static function parseLotusNotesId(string $lotusNotesId): string
    {
        $arr = explode('/', $lotusNotesId);
        $idArr = [];
        foreach ($arr as $value) {
            $value = explode('=', $value);
            $value = $value[1] ?? null;
            if ($value === null) {
                continue;
            }
            $idArr[] = $value;
        }

        $id = implode('/', $idArr);

        if (($pos = strpos($id, '@')) !== false) {
            $id = substr($id, 0, $pos);
        }

        return $id;
    }

    /**
     * Returns the identifier of the authorized resource owner.
     *
     * @return string
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getId(): string
    {
        return $this->response['sub'] ?? '';
    }

    /**
     * Get resource owner email
     *
     * @return string
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getEmail(): string
    {
        return strtolower($this->response['email']) ?? '';
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->response;
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getFullName(): string
    {
        return $this->response['name'] ?? '';
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getCnum(): string
    {
        return $this->attributes['cnum'] ?? '';
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getLotusNotesId(): string
    {
        $lotusNotesId = $this->attributes['lotusnotesid'] ?? '';
        if (empty($lotusNotesId)) {
            return $lotusNotesId;
        }

        return self::parseLotusNotesId($lotusNotesId);
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return array
     */
    public function getIbmInfo(): array
    {
        return $this->attributes['ibminfo'] ?? [];
    }

    /**
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     * @return string
     */
    public function getLocation(): string
    {
        return $this->attributes['locate'] ?? '';
    }

    /**
     * @return string
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    public function getUid(): string
    {
        return $this->attributes['uid'] ?? '';
    }

    /**
     * @return array
     * @author Dzianis Kotau <jampire.blr@gmail.com>
     */
    private function getAttributes(): array
    {
        $response = $this->response;
        if (empty($response['identities'])
                  || empty($response['identities'][0])
                  || empty($response['identities'][0]['idpUserInfo'])
                  || empty($response['identities'][0]['idpUserInfo']['attributes'])) {
            return [];
        }

        return $response['identities'][0]['idpUserInfo']['attributes'];
    }
}
