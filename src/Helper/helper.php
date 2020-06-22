<?php

use Hyperf\Utils\Context;

/**
 * 下划线 转 驼峰
 */
if (!function_exists('convertUnderline')) {
    function convertUnderline($str)
    {
        $str = preg_replace_callback('/([-_]+([a-z]{1}))/i', function ($matches) {
            return strtoupper($matches[2]);
        }, $str);
        return $str;
    }
}
/**
 * 驼峰 转 下划线
 */
if (!function_exists('humpToLine')) {
    function humpToLine($str)
    {
        $str = preg_replace_callback('/([A-Z]{1})/', function ($matches) {
            return '_' . strtolower($matches[0]);
        }, $str);
        return $str;
    }
}
