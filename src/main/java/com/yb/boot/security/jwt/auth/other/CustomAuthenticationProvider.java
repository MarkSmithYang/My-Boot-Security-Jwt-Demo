package com.yb.boot.security.jwt.auth.other;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * @author yangbiao
 * @Description:自定义身份认证类
 * @date 2018/11/30
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    /**
     * 自定义认证的实现方法
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //把对象转换为json字符串,传递到loadUserByUsername里进行处理,这样可以减少查询用户的次数
        String authen = JSONObject.toJSON(authentication).toString();
        //获取Security自带的详情信息(主要是用户名密码一级一些锁定账户,账户是否可用的信息)
        UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(authen);
        //构造token对象--因为在那边已经sysUser会抛出异常,所以正常返回的都是能构造成功的,所以UserDetails不会为空
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
        //设置用户详情信息
        token.setDetails(userDetails);
        //返回令牌信息
        return token;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        //是否可以提供输入类型的认证服务
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }


}
