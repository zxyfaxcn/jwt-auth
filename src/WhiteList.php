<?php

declare(strict_types=1);

namespace JwtAuth;

use Hyperf\Config\Annotation\Value;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\Redis;

class WhiteList
{
    #[Value("jwt.login_type")]
    protected string $loginType;

    #[Value("jwt.sso_key")]
    protected string $ssoKey;

    #[Value("jwt.cache_prefix")]
    private string $cache_prefix;

    #[Inject]
    protected Redis $redis;

    /**
     * 是否有效已经加入白名单
     */
    public function effective(array $payload): bool
    {
        if ($this->loginType === JWT::LOGIN_TYPE_MPOP) {
            return true;
        }
        if ($this->loginType === JWT::LOGIN_TYPE_SSO) {
            $val = $this->redis->get($this->cache_prefix . $payload['scope'] . ":" . $payload['aud']);
            return $payload['jti'] === $val;
        }
        return false;
    }

    /**
     * 添加白名单
     */
    public function add($uid, string $type, $version, $ttl): bool
    {
        return $this->redis->setex($this->cache_prefix . $type . ":" . $uid, $ttl, $version);
    }

    /**
     * 移出白名单, 强制T出登录
     */
    public function remove($uid, $type = Jwt::SCOPE_TOKEN): bool
    {
        return $this->redis->del($this->cache_prefix . $type . ":" . $uid);
    }
}
