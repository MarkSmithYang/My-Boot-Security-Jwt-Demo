package com.yb.springsecurity.jwt.authsecurity;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.common.ResultInfo;
import io.jsonwebtoken.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * author yangbiao
 * Description:Token的生成认证服务--JWT登录过滤和认证的过滤会用到它生成JWT
 * date 2018/11/30
 */
public class TokenAuthenticationService {
    public static final Logger log = LoggerFactory.getLogger(TokenAuthenticationService.class);

    public static final long EXPIRATION_TIME = 30 * 60 * 1000;//30分钟的过期时间
    public static final String SECRET = "P@ssw0rd";//jwt秘钥
    public static final String TOKEN_PREFIX = "Bearer";//token的前缀
    public static final String HEADER_SINGLE = "Authorization";//请求头Header的token的key

    /**
     * 生成jwt并写入body
     */
    public static void addAuthentication(HttpServletResponse response, String username) {
        //生成JWT
        String jwt = Jwts.builder()
                //保存权限(角色),该方法是往JWT添加key和对应的value
                .claim("authorities", "admin,write")
                //添加用户名到主题
                .setSubject(username)
                //有效期设置
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                //签名设置
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        //将JWT写入body
        try {
            response.setContentType("applicaton/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getOutputStream().println(JSONObject.toJSONString(ResultInfo.success(jwt)));
        } catch (IOException e) {
            log.info("将jwt写入body异常");
            e.printStackTrace();
        }
    }

    /**
     * 认证token合法性并返回
     */
    public static Authentication getAuthentication(HttpServletRequest request) {
        //从请求头获取token
        String token = request.getHeader(HEADER_SINGLE);
        //token不为空时解析token信息
        if (StringUtils.isNotBlank(token)) {
            //解析解析token
            Claims claims = Jwts.parser()
                    //验证签名
                    .setSigningKey(SECRET)
                    //取消token的头Bearer
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                    .getBody();
            //获取用户名
            String username = claims.getSubject();
            //获取权限(角色)信息,claims.get("authorities")取的就是之前添加的admin和write
            List<GrantedAuthority> authorities =
                    AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
            //返回验证令牌
            return StringUtils.isNotBlank(username) ?
                    new UsernamePasswordAuthenticationToken(username, null, authorities) : null;
        }
        return null;
    }

}
