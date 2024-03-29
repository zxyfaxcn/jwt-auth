### 基于Hyperf(https://doc.hyperf.io/#/zh/README) 框架的 jwt 鉴权
### 思路来源与 (https://github.com/phper666/jwt-auth)组件
### 重构sso单点登录token失效逻辑
### 说明：

> `hyperf-jwt` 支持单点登录、多点登录、支持注销 token(token会失效)、支持refresh换取新token 失效老token  
  
> 单点登录：只会有一个 token 生效，一旦刷新 token ，前面生成的 token 都会失效，一般以用户 id 来做区分  
  
> 多点登录：token 不做限制
  
> 单点登录原理：token版本号，`JWT` 单点登录必须用到 aud（接收方） 默认字段，`aud` 字段的值默认为用户 id。当生成 token 时，会更新白名单uid的key值为当前的版本号，但是如果是调用 `refreshToken` 来刷新 token 或者调用 `logout` 注销token，默认前面生成的 token 都会失效。  
  如果开启单点登录模式，每次验证时候会查询当前uid的对应key是否和当前的版本号对应
  
> token 不做限制原理：token 不做限制，在 token 有效的时间内都能使用


### 使用：
##### 1、安装依赖 
```shell
composer require zxyfaxcn/jwt-auth
``` 

##### 2、发布配置
```shell
php bin/hyperf.php vendor:publish zxyfaxcn/jwt-auth
```

##### 3、jwt配置
去配置 `config/autoload/jwt.php` 文件或者在配置文件 `.env` 里配置
```shell
# 务必改为你自己的字符串
JWT_SECRET=hyperf
#token过期时间，单位为秒
JWT_TTL=60
```
更多的配置请到 `config/autoload/jwt.php` 查看

##### 4、模拟登录获取token
```shell
<?php

namespace App\Controller;
use JwtAuth\Jwt;
class IndexController extends Controller
{
    # 模拟登录,获取token
    public function login(Jwt $jwt)
    {
        #用法1: 传入对象

        $jwtData = new JwtBuilder();
        $jwtData->setIssuer('api');
        $jwtData->setAudience('xxx');
        #... 设置更多token属性

        #... 设置data数据
        $jwtData->setJwtData(['uid' => 123, 'type' => 1111, 'group' => 1]);

        #返回 JwtBuilder对象
        $tokenObj = $jwt->createToken($jwtData);

        #获取生成的token 
        $tokenObj->getToken();  


        #用法2: 传入数组 

        #初始化JwtBuilder对象
        $tokenObj = $jwt->createToken(['uid' => $id, 'type' => $type, 'group' => $group]);

        #获取生成的token 
        $tokenObj->getToken();  

        #获取刷新token 传入数组  第一个参数为数据，第二个参数为类型，默认是access 可以定义为 refersh 或者其他类型自定义
        #返回 JwtBuilder对象  
        $tokenObj = $jwt->createToken(['uid' => $id, 'type' => $type, 'group' => $group], Jwt::SCOPE_REFRESH);

        #获取生成的token 
        $tokenObj->getToken();  

        return $tokenObj->getToken();
    }
}
```
注意：支持传入用户对象获取 token，支持token类型，

##### 5、建议
> 目前 `jwt` 抛出的异常目前有两种类型 `JwtAuth\Exception\TokenValidException` 和 `JwtAuth\Exception\JWTException,TokenValidException` 异常为 token 验证失败的异常，会抛出 `401` ,`JWTException` 异常会抛出 `500`，最好你们自己在项目异常重新返回错误信息
