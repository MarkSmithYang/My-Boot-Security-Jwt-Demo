package com.yb.springsecurity.jwt.authsecurity;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.common.ResultInfo;
import com.yb.springsecurity.jwt.model.SysUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * author yangbiao
 * Description:处理所有JWT相关内容的类
 * date 2018/11/30
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

    public JWTLoginFilter(String url, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
       //JSON反序列化为传入的对象
        SysUser sysUser = JSONObject.parseObject(request.getInputStream(), SysUser.class);
        return sysUser!=null?getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(sysUser.getUsername(),
                sysUser.getPassword())):null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
       //认证成功后生成jwt并写入body
        TokenAuthenticationService.addAuthentication(response, authResult.getName());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        //认证不成功时body写入错误提示信息
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getOutputStream().println(JSONObject.toJSONString(ResultInfo.error("Internal Server Error!!!")));
    }
}
