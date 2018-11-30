package com.yb.springsecurity.jwt.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * author yangbiao
 * Description:验证其他请求token是否合法的类 OncePerRequestFilter继承GenericFilterBean了, 并扩展了内容
 * date 2018/11/30
 */
public class JWTAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        //如果继承了OncePerRequestFilter就不需要强转了
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        //获取请求token认证通过返回的Authentication信息
        Authentication authentication = TokenAuthenticationService.getAuthentication(request);
        //把Authentication信息set到SecurityContext里,如果没校验通过返回null也就是用户的认证信息为空
        //这个用户认证信息(Authentication)是放在ThreadLocal里的
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //执行过滤
        chain.doFilter(request, response);
    }
}
