package com.yb.springsecurity.jwt.authsecurity;

import com.yb.springsecurity.jwt.service.SecurityJwtService;
import com.yb.springsecurity.jwt.service.UserDetailsServiceImpl;
import com.yb.springsecurity.jwt.utils.PasswordEncryptUtils;
import com.yb.springsecurity.jwt.exception.ParameterErrorException;
import com.yb.springsecurity.jwt.model.SysUser;
import com.yb.springsecurity.jwt.repository.SysUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author yangbiao
 * @Description:自定义身份认证类
 * @date 2018/11/30
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private SysUserRepository sysUserRepository;
    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;
    @Autowired
    private SecurityJwtService securityJwtService;

    /**
     * 自定义认证的实现方法
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //获取需要认证的用户名
        String username = (String) authentication.getPrincipal();
        //获取需要认证的密码
        String password = authentication.getCredentials().toString();
        //获取from
        String from = null;
        //判断参数是否属于自定义的token,是则强转获取from
        //(因为是用这个new MyUsernamePasswordAuthenticationToken传递进来的,其实不用判断所属也可以直接强转的)
        if (authentication instanceof MyUsernamePasswordAuthenticationToken) {
            from = ((MyUsernamePasswordAuthenticationToken) authentication).getFrom();
        }
        //进行自定义的逻辑认证--(如果用户名可能是电话号码,邮箱地址,用户名,这个需要逐个去查询判断)
        SysUser sysUser = sysUserRepository.findByUsername(username);
        //判断用户名是否正确
        if (sysUser == null) {
            ParameterErrorException.message("用户名或密码错误");
        }
        //判断用户密码是否正确
        if (!PasswordEncryptUtils.matchPassword(password, sysUser.getPassword())) {
            ParameterErrorException.message("用户名或密码错误");
        }
        //获取Security自带的详情信息(主要是用户名密码一级一些锁定账户,账户是否可用的信息)
        UserDetails userDetails = userDetailsServiceImpl.loadUserById(sysUser.getId());
        //获取权限信息-->一般来说不去获取UserDetails也没有什么问题,除非想用一些类似于锁定账户等功能的时候
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        //构造token对象
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), null, authorities);
        //设置用户详情信息
        token.setDetails(userDetails);
        //把相关的用户详情信息(角色权限部门电话等等信息)封装并存入redis里(from作为拼接的字符串)
        securityJwtService.setUserDetailsInfo(sysUser, from);
        //返回令牌信息
        return token;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        //是否可以提供输入类型的认证服务
        return false;
    }
}
