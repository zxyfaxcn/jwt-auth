<?php

declare(strict_types=1);

namespace JwtAuth;

class JwtBuilder implements \ArrayAccess
{
    private $container = [];

    protected $token = '';
    protected $refresh_token = '';

    public function __construct($container = [])
    {
        $this->container = $container;
    }

    /**
     * 以对象的方式访问数组中的数据
     *
     * @param $key
     * @return mixed
     */
    public function __get($key)
    {
        return $this->container[$key];
    }

    /**
     * 以对象方式添加一个数组元素
     *
     * @param $key
     * @param $val
     */
    public function __set($key, $val)
    {
        $this->container[$key] = $val;
    }

    /**
     * 以对象方式判断数组元素是否设置
     *
     * @param $key
     * @return bool
     */
    public function __isset($key)
    {
        return isset($this->container[$key]);
    }

    /**
     * 以对象方式删除一个数组元素
     *
     * @param $key
     */
    public function __unset($key)
    {
        unset($this->container[$key]);
    }

    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    public function offsetExists($offset)
    {
        return isset($this->container[$offset]);
    }

    public function offsetUnset($offset)
    {
        unset($this->container[$offset]);
    }

    public function offsetGet($offset)
    {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    public function toArray()
    {
        return $this->container;
    }

    /**
     * 发行人
     * @return mixed
     */
    public function getIssuer()
    {
        return $this->container['iss'] ?? '';
    }

    /**
     * 发行人
     * @param mixed $issuer
     */
    public function setIssuer($issuer): void
    {
        $this->container['iss'] = $issuer;
    }

    /**
     * jwt所面向的用户
     * @return mixed
     */
    public function getSubject()
    {
        return $this->container['sub'] ?? '';
    }

    /**
     * @param mixed $subject
     */
    public function setSubject($subject): void
    {
        $this->container['sub'] = $subject;

    }

    /**
     * 接收jwt的一方
     * @return mixed
     */
    public function getAudience()
    {
        return $this->container['aud'] ?? '';
    }

    /**
     * 接收jwt的一方
     * @param mixed $audience
     */
    public function setAudience($audience): void
    {
        $this->container['aud'] = $audience;
    }

    /**
     * jwt的过期时间，这个过期时间必须要大于签发时间
     * @return mixed
     */
    public function getExpiration()
    {
        return $this->container['exp'] ?? '';
    }

    /**
     * jwt的过期时间，这个过期时间必须要大于签发时间
     * @param mixed $expiration
     */
    public function setExpiration($expiration): void
    {
        $this->container['exp'] = $expiration;
    }

    /**
     * 定义在什么时间之前，该jwt都是不可用的.
     * @return mixed
     */
    public function getNotBefore()
    {
        return $this->container['nbf'] ?? '';
    }

    /**
     * 定义在什么时间之前，该jwt都是不可用的.
     * @param mixed $notBefore
     */
    public function setNotBefore($notBefore): void
    {
        $this->container['nbf'] = $notBefore;
    }

    /**
     * jwt的签发时间
     * @return mixed
     */
    public function getIssuedAt()
    {
        return $this->container['iat'] ?? '';
    }

    /**
     * jwt的签发时间
     * @param mixed $issuedAt
     */
    public function setIssuedAt($issuedAt): void
    {
        $this->container['iat'] = $issuedAt;
    }

    /**
     * jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
     * @return mixed
     */
    public function getJwtId()
    {
        return $this->container['jti'] ?? '';
    }

    /**
     * jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
     * @param mixed $jwtId
     */
    public function setJwtId($jwtId): void
    {
        $this->container['jti'] = $jwtId;
    }

    /**
     * 自定义操作类型, SCOPE_TOKEN / SCOPE_REFRESH
     * @return mixed
     */
    public function getScope()
    {
        return $this->container['scope'] ?? '';
    }

    /**
     * 自定义操作类型, SCOPE_TOKEN / SCOPE_REFRESH
     */
    public function setScope($scope): void
    {
        $this->container['scope'] = $scope;
    }

    /**
     * 自定义数据（不可以写敏感信息, 会以base64的方式包含在jwt token串中）
     * @return mixed
     */
    public function getJwtData()
    {
        return $this->container['data'] ?? [];
    }

    /**
     * 自定义数据
     * @param mixed $jwtData
     */
    public function setJwtData(array $jwtData): void
    {
        $this->container['data'] = $jwtData;
    }

    /**
     * 鉴权Token
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * 鉴权Token
     * @param string $token
     * @return JwtBuilder
     */
    public function setToken(string $token): JwtBuilder
    {
        $this->token = $token;
        return $this;
    }

    /**
     * 刷新Token
     * @return string
     */
    public function getRefreshToken(): string
    {
        return $this->refresh_token;
    }

    /**
     * 刷新Token
     * @param string $refresh_token
     */
    public function setRefreshToken(string $refresh_token): void
    {
        $this->refresh_token = $refresh_token;
    }
}
