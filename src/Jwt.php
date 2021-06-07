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
    const SCOPE_TOKEN = 'access';
    const SCOPE_REFRESH = 'refresh';

    //头部
    private static $header = [
        'alg' => 'HS256', //生成signature的算法
        'typ' => 'JWT', //类型
    ];

    /**
     * @Inject()
     * @var WhiteList
     */
    protected $whiteList;

    /**
     * 加密算法
     * @Value("jwt.alg")
     * @var string
     */
    protected $alg;

    /**
     * 登录方式 sso/mpop
     * @Value("jwt.login_type")
     * @var string
     */
    protected $loginType;

    /**
     * 自定义的 key, 用以处理单点登录
     * @Value("jwt.sso_key")
     * @var string
     */
    protected $ssoKey;

    /**
     * @Value("jwt.ttl")
     * @var int
     */
    protected $ttl;

    /**
     * @Value("jwt.refresh_ttl")
     * @var int
     */
    protected $refreshTtl;

    /**
     * @Value("jwt.secret")
     * @var string
     */
    private $secret;

    /**
     * 创建jtw token
     * @param array|JwtBuilder $payload jwt载荷
     * @param string $scope
     * @return JwtBuilder
     */
    public function createToken($payload, $scope = Jwt::SCOPE_TOKEN)
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

        switch ($scope) {
            case self::SCOPE_TOKEN:
                $ttl = $this->ttl;
                break;
            case self::SCOPE_REFRESH:
                $ttl = $this->refreshTtl;
                break;
            default:
                throw new JWTException('Unsupported operation');
        }
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
        $base64header = self::base64UrlEncode(json_encode(['alg' => $this->alg, 'typ' => 'JWT'], JSON_UNESCAPED_UNICODE));
        $base64payload = self::base64UrlEncode(json_encode($jwtObj->toArray(), JSON_UNESCAPED_UNICODE));
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
     * @param string $Token 需要验证的token
     * @return JwtBuilder
     * @throws TokenValidException
     */
    public function verifyToken(string $Token)
    {
        $tokenArray = explode('.', $Token);
        if (3 != count($tokenArray)) {
            throw new TokenValidException('token格式不对', 401);
        }
        list($base64header, $base64payload, $sign) = $tokenArray;
        //获取jwt算法
        try {
            $base64deadheaded = json_decode(self::base64UrlDecode($base64header), true, 512, JSON_THROW_ON_ERROR);
            if (empty($base64deadheaded['alg'])) {
                throw new TokenValidException('token 错误', 401);
            }
            //签名验证
            if (self::signature($base64header . '.' . $base64payload, $this->secret, $base64deadheaded['alg']) !== $sign) {
                throw new TokenValidException('token签名错误', 500);
            }
            $payload = json_decode(self::base64UrlDecode($base64payload), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new TokenValidException('token解析无效', 500);
        }
        switch (true) {
            case isset($payload['scope']) && $payload['scope'] != Jwt::SCOPE_TOKEN:
                throw new TokenValidException('token类型无效', 401);
            case isset($payload['iat']) && $payload['iat'] > time(): //检查签发时间
            case isset($payload['exp']) && $payload['exp'] < time()://检查过期时间
            case !$this->whiteList->effective($payload)://检查白名单情况
                throw new TokenValidException('token已失效', 401);
            case isset($payload['nbf']) && $payload['nbf'] > time(): //检查是否生效
                throw new TokenValidException('token未生效', 401);
        }
        return new JwtBuilder($payload);
    }

    /**
     * 验证token是否有效,默认验证exp,nbf,iat时间
     * @param string $Token 需要验证的token
     * @return JwtBuilder
     */
    public function verifyRefreshToken(string $Token)
    {
        $tokenArray = explode('.', $Token);
        if (3 != count($tokenArray)) {
            throw new TokenValidException('token格式不对', 401);
        }
        list($base64header, $base64payload, $sign) = $tokenArray;
        //获取jwt算法
        try {
            $base64deadheaded = json_decode(self::base64UrlDecode($base64header), true);
            if (empty($base64deadheaded['alg'])) {
                throw new TokenValidException('token 错误', 401);
            }
            //签名验证
            if (self::signature($base64header . '.' . $base64payload, $this->secret, $base64deadheaded['alg']) !== $sign) {
                throw new TokenValidException('token签名错误', 500);
            }
            $payload = json_decode(self::base64UrlDecode($base64payload), true);
        } catch (\Throwable $e) {
            throw new TokenValidException('token解析无效', 500);
        }
        switch (true) {
            case isset($payload['scope']) && $payload['scope'] != Jwt::SCOPE_REFRESH:
                throw new TokenValidException('token 类型无效', 401);
            case isset($payload['iat']) && $payload['iat'] > time(): //检查签发时间
            case isset($payload['exp']) && $payload['exp'] < time()://检查过期时间
            case !$this->whiteList->effective($payload)://检查白名单情况
                throw new TokenValidException('token已失效', 401);
            case isset($payload['nbf']) && $payload['nbf'] > time(): //检查是否生效
                throw new TokenValidException('token未生效', 401);
        }
        return new JwtBuilder($payload);
    }

    /**
     * base64UrlEncode  https://jwt.io/ 中base64UrlEncode编码实现
     * @param string $input 需要编码的字符串
     * @return string
     */
    private static function base64UrlEncode(string $input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode https://jwt.io/ 中base64UrlEncode解码实现
     * @param string $input 需要解码的字符串
     * @return bool|string
     */
    private static function base64UrlDecode(string $input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMACSHA256签名  https://jwt.io/ 中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key 自定义密钥
     * @param string $alg 算法方式
     * @return mixed
     */
    private static function signature(string $input, string $key, string $alg = 'HS256')
    {
        $alg_config = array(
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512'
        );
        return self::base64UrlEncode(hash_hmac($alg_config[$alg], $input, $key, true));
    }
}
