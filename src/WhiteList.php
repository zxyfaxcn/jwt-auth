<?php

declare(strict_types=1);

namespace JwtAuth;

use Hyperf\Config\Annotation\Value;
use Hyperf\Di\Annotation\Inject;

class WhiteList
{
    /**
     * @Value("jwt.login_type")
     * @var string
     */
    protected $loginType;

    /**
     * @Value("jwt.sso_key")
     * @var string
     */
    protected $ssoKey;

    /**
     * @Value("jwt.cache_prefix")
     * @var string
     */
    private $cache_prefix;

    /**
     * @Inject()
     * @var \Redis
     */
    protected $redis;

    /**
     * 是否有效已经加入白名单
     * @param array $payload
     * @return bool
     */
    public function effective(array $payload)
    {
        switch (true) {
            case ($this->loginType === 'mpop'):
                return true;
            case ($this->loginType === 'sso'):
                $val = $this->redis->get($this->cache_prefix . $payload['scope'] . ":" . $payload['aud']);
                return $payload['jti'] === $val;
            default:
                return false;
        }
    }

    /**
     * 添加白名单
     * @param $uid
     * @param $version
     * @param string $type
     * @return bool
     */
    public function add($uid, $type, $version, $ttl)
    {
        return $this->redis->setex($this->cache_prefix . $type . ":" . $uid, $ttl, $version);
    }

    /**
     * 移出白名单, 强制T出登录
     * @param $uid
     * @param string $type
     * @return bool
     */
    public function remove($uid, $type = Jwt::SCOPE_TOKEN)
    {
        return $this->redis->del($this->cache_prefix . $type . ":" . $uid);
    }
}
