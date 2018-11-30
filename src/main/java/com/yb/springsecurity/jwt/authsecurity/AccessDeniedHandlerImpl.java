package com.yb.springsecurity.jwt.authsecurity;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.common.ResultInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
  * Description: ajxa处理类
  * author yangbiao
  * date 2018/11/30
 */
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setStatus(403);
        ResultInfo info = ResultInfo.status(HttpServletResponse.SC_FORBIDDEN).message("权限不足");
        response.getOutputStream().write(JSONObject.toJSON(info).toString().getBytes());
    }
}
