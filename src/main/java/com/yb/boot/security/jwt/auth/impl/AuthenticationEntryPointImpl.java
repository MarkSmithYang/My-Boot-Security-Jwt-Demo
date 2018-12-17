package com.yb.boot.security.jwt.auth.impl;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.common.ResultInfo;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * author yangbiao
 * Description:统一处理未登录的无权访问的类
 * date 2018/11/30
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        ResultInfo info = ResultInfo.status(HttpServletResponse.SC_UNAUTHORIZED).message("请登录");
        response.getOutputStream().write(JSONObject.toJSON(info).toString().getBytes());
    }
}
