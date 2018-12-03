package com.yb.springsecurity.jwt.common;

/**
 * @author yangbiao
 * @Description:关于token的静态变量
 * @date 2018/11/20
 */
public class CommonDic {
    //请求头Header里的token的key静态变量
    public static final String HEADER_NAME = "Authentication";
    public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    public static final String USERNAME_PASSWORD_AUTHENTICATION_TOKEN =
            "USERNAME_PASSWORD_AUTHENTICATION_TOKEN";
    //过期时间设置
    public static final long TOKEN_EXPIRE = 30;//分钟
    public static final long RETOKEN_EXPIRE = 7 * 24 * 60;//分钟
    //ajxa处理类用
    public static final String SECURITY_CONTEXT = "SECURITY_CONTEXT";
    //登录的来源
    public static final String FROM_FRONT = "front";//前台
    public static final String FROM_BACK = "back";//后台
    //登陆的前缀字典
    public static final String LOGIN_SIGN_PRE = "LOGIN_SIGN_PRE";
    //验证码刷新限制次数和验证码位数和验证码存储时间
    public static final String VERIFYCODE_SIGN_PRE = "VERIFYCODE_SIGN_PRE";
    public static final int REQUEST_MAX_TIMES = 15;
    public static final int VERIFYCODE_AMOUNT = 4;
    public static final int VERIFYCODE_EXPIRED = 60;
    //用户正常登录的允许次数,高于此次数,需要增加用户的等待时间
    public static final String _IP_FORBIDDEN_ = "_IP_FORBIDDEN_";
    public static final String _USERNAME_ONE_DAY_FORBIDDEN_ = "_USERNAME_ONE_DAY_FORBIDDEN_";
    public static final String LOGIN_TIMES_PRE = "LOGIN_TIMES_PRE";
    //用户详情信息封装类
    public static final String USER_DETAILS_INFO = "USER_DETAILS_INFO";
    //记住我秒数
    public static final int REMEMBER_ME_TIME = 7 * 24 * 60 * 60;
    //jwt唯一标识jti的存储key
    public static final String USER_JWT_JTI = "USER_JWT_JTI";
    //token的前缀
    public static final String TOKEN_PREFIX = "Bearer ";
    //请求头Header的token的key
    public static final String HEADER_SINGLE = "Authorization";

}
