<?php

declare(strict_types=1);

namespace JwtAuth;

use Hyperf\Config\Annotation\Value;
use Hyperf\Di\Annotation\Inject;
use JwtAuth\Exception\JWTException;
use JwtAuth\Exception\TokenValidException;

/**
 * PHP实现jwt
 */
class Jwt
{
    public const LOGIN_TYPE_SSO = 'sso';
    public const LOGIN_TYPE_MPOP = 'mpop';

    public const SCOPE_TOKEN = 'access';
    public const SCOPE_REFRESH = 'refresh';

    // 头部
    private const HEADER = [
        'alg' => 'HS256', // 生成signature的算法
        'typ' => 'JWT', // 类型
    ];

    #[Inject]
    protected WhiteList $whiteList;

    /**
     * 加密算法
     */
    #[Value("jwt.alg")]
    protected string $alg;

    /**
     * 登录方式 sso/mpop
     */
    #[Value("jwt.login_type")]
    protected string $loginType;

    /**
     * 自定义的 key, 用以处理单点登录
     */
    #[Value("jwt.sso_key")]
    protected string $ssoKey;

    #[Value("jwt.ttl")]
    protected int $ttl;

    #[Value("jwt.refresh_ttl")]
    protected int $refreshTtl;

    #[Value("jwt.secret")]
    private string $secret;

    /**
     * 创建jtw token
     */
    public function createToken(array|JwtBuilder $payload, string $scope = Jwt::SCOPE_TOKEN): JwtBuilder
    {
        $time = time();

        if ($payload instanceof JwtBuilder) {
            $jwtObj = $payload;
            $jwtObj->setScope($scope);
            if (empty($jwtObj->getIssuedAt())) {
                $jwtObj->setIssuedAt($time);
            }
            if (empty($jwtObj->getNotBefore())) {
                $jwtObj->setNotBefore($time);
            }
        } else {
            $jwtObj = new JwtBuilder();
            if (isset($payload[$this->ssoKey])) {
                $jwtObj->setAudience($payload[$this->ssoKey]);
            }
            $jwtObj->setJwtData($payload);
            $jwtObj->setScope($scope);
            $jwtObj->setIssuedAt($time);
            $jwtObj->setNotBefore($time);
        }

        $ttl = match ($scope) {
            self::SCOPE_TOKEN => $this->ttl,
            self::SCOPE_REFRESH => $this->refreshTtl,
            default => throw new JWTException('Unsupported operation'),
        };
        $jwtObj->setExpiration($time + $ttl);

        // 设置jwt的jti
        $version = uniqid('', true);
        $jwtObj->setJwtId($version);

        // 单点必须设置aud（用这个标识来设定用户登录白名单）
        if ($this->loginType === 'sso' && $jwtObj->getAudience() === '') {
            throw new JWTException("There is no Audience key in the claims");
        }
        if ($this->loginType === 'sso') {
            // 添加白名单, access : uid . jti标识 \ refresh : uid . jti标识
            $this->whiteList->add($jwtObj->getAudience(), $jwtObj->getScope(), $version, $ttl);
        }

        // 生成Token
        $base64header = self::base64UrlEncode(json_encode(['alg' => $this->alg, 'typ' => self::HEADER['typ']], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
        $base64payload = self::base64UrlEncode(json_encode($jwtObj->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
        switch ($jwtObj->getScope()) {
            case self::SCOPE_TOKEN:
                $jwtObj->setToken($base64header . '.' . $base64payload . '.' . self::signature($base64header . '.' . $base64payload, $this->secret, $this->alg));
                break;
            case self::SCOPE_REFRESH:
                $jwtObj->setRefreshToken($base64header . '.' . $base64payload . '.' . self::signature($base64header . '.' . $base64payload, $this->secret, $this->alg));
                break;
        }
        return $jwtObj;
    }

    /**
     * 验证token是否有效,默认验证exp,nbf,iat时间
     */
    public function verifyToken(string $token, string $type = self::SCOPE_TOKEN): JwtBuilder
    {
        $payload = $this->parseToken($token);
        switch (true) {
            case isset($payload['scope']) && $payload['scope'] !== $type:
                throw new TokenValidException('token类型无效', 401);
            case isset($payload['iat']) && $payload['iat'] > time(): // 检查签发时间
            case isset($payload['exp']) && $payload['exp'] < time(): // 检查过期时间
            case ! $this->whiteList->effective($payload): // 检查白名单情况
                throw new TokenValidException('token已失效', 401);
            case isset($payload['nbf']) && $payload['nbf'] > time(): // 检查是否生效
                throw new TokenValidException('token未生效', 401);
        }
        return new JwtBuilder($payload);
    }

    private function parseToken(string $token)
    {
        $tokenArray = explode('.', $token);
        if (count($tokenArray) !== 3) {
            throw new TokenValidException('token格式不对', 401);
        }
        [$base64header, $base64payload, $sign] = $tokenArray;
        // 获取jwt算法
        try {
            $base64deadheaded = json_decode(self::base64UrlDecode($base64header), true, 512, JSON_THROW_ON_ERROR);
            if (empty($base64deadheaded['alg'])) {
                throw new TokenValidException('token 错误', 401);
            }
            // 签名验证
            if (self::signature($base64header . '.' . $base64payload, $this->secret, $base64deadheaded['alg']) !== $sign) {
                throw new TokenValidException('token签名错误', 500);
            }
            return json_decode(self::base64UrlDecode($base64payload), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new TokenValidException('token解析无效', 500);
        }
    }

    /**
     * base64UrlEncode  https://jwt.io/ 中base64UrlEncode编码实现
     */
    private static function base64UrlEncode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode https://jwt.io/ 中base64UrlEncode解码实现
     */
    private static function base64UrlDecode(string $input): bool|string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addLen = 4 - $remainder;
            $input .= str_repeat('=', $addLen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMACSHA256签名  https://jwt.io/ 中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key 自定义密钥
     * @param string $alg 算法方式
     */
    private static function signature(string $input, string $key, string $alg = self::HEADER['alg']): string
    {
        $alg_config = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512'
        ];
        return self::base64UrlEncode(hash_hmac($alg_config[$alg], $input, $key, true));
    }
}
