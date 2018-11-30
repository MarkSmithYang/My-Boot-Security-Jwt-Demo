package com.yb.springsecurity.jwt.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * author yangbiao
 * Description:用户密码加密工具
 * date 2018/11/30
 */
public class PasswordEncryptUtils {

    /**
     * 密码加密
     * @param password
     * @return
     */
    public static String passwordEncoder(String password){
        //给输入的密码加密
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encode = encoder.encode(password.trim());
        return encode;
    }

    /**
     * 密码匹配校验
     * @param password
     * @param dbPassword
     * @return
     */
    public static boolean matchPassword(String password,String dbPassword){
        //使用BCryptPasswordEncoder自带的校验api
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.matches(password, dbPassword);
    }

}
