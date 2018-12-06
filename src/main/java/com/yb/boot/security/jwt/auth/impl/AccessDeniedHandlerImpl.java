package com.yb.boot.security.jwt.auth.impl;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.common.ResultInfo;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

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
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        //判断请求
        if (isAjaxRequest(request)) {
            // AJAX请求,使用response发送403
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        } else if (!response.isCommitted()) {
            // 非AJAX请求
            ResultInfo info = ResultInfo.status(HttpServletResponse.SC_FORBIDDEN).message("权限不足");
            response.getOutputStream().write(JSONObject.toJSON(info).toString().getBytes());
        }
    }

    /**
     * 判断是否为ajax请求
     */
    public boolean isAjaxRequest(HttpServletRequest request) {
        if (request.getHeader("accept").indexOf("application/json") > -1
                || (request.getHeader("X-Requested-With") != null && request.getHeader("X-Requested-With").equals(
                "XMLHttpRequest"))) {
            return true;
        }
        return false;
    }
}
