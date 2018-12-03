package com.yb.springsecurity.jwt.auth.tools;

import com.yb.springsecurity.jwt.common.CommonDic;
import com.yb.springsecurity.jwt.common.JwtProperties;
import com.yb.springsecurity.jwt.response.UserDetailsInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.*;

/**
 * Description:Jwt的token工具
 * author yangbiao
 * date 2018/11/30
 */
@Component
public class JwtTokenTools {
    public static final Logger log = LoggerFactory.getLogger(JwtTokenTools.class);

    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private RedisTemplate<String, Serializable> redisTemplate;

    /**
     * 生成jwt令牌
     */
    public String createAccessToken(UserDetailsInfo detailsInfo,HttpServletResponse response) {
        //生成jti
        String jti = getJti();
        //存储jwt的唯一标识jti
        redisTemplate.opsForValue().set(CommonDic.USER_JWT_JTI + detailsInfo.getUsername(), jti);
        //创建jwt(token)
        String token = Jwts.builder()
                //说明类型为JWT(签名算法就不说了,怕与下面的冲突)
                .setHeaderParam("typ", "JWT")
                //签发者设置--------->claim部分
                .claim(CommonDic.USER_DETAILS_INFO, detailsInfo)
                //设置发布人
                .setIssuer(jwtProperties.getIss())
                //接收jwt的一方(观众)
                .setAudience(jwtProperties.getAud())
                //jwt(token)所面向的用户(一般都是用户名)
                .setSubject(detailsInfo.getUsername())
                //设置jwt(token)的过期时间
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpireSeconds()))
                //设置jwt(token)的签发时间--->因为parse的时候没法指定时间,所以觉得设置了也什么用
                //.setIssuedAt(new Date())
                //设置在什么时间之前token不可用--->因为parse的时候没法指定时间,所以觉得设置了也什么用
                //.setNotBefore(new Date(System.currentTimeMillis()))
                //设置jwt(token)的唯一标识jti
                .setId(jti)
                //签名设置--(设置加密算法)-------->签名部分
                .signWith(SignatureAlgorithm.HS512, jwtProperties.getSecret() + detailsInfo.getUsername())
                //这个是全部设置完成后拼成jwt串的方法
                .compact();
        //把jwt写入header
        response.setHeader(CommonDic.HEADER_SINGLE, CommonDic.TOKEN_PREFIX + token);
        //返回jwt字符串
        return token;
    }

    /**
     * 解析Jwt字符串
     */
    public UserDetailsInfo parseJwt(HttpServletRequest request, String username) {
        //获取redis该用户存储的jti
        String jti = (String) redisTemplate.opsForValue().get(CommonDic.USER_JWT_JTI + username);
        //获取请求头里的token值
        String token = request.getHeader(CommonDic.HEADER_SINGLE);
        //判断token是否为空
        if (StringUtils.isBlank(token) && !token.startsWith(CommonDic.TOKEN_PREFIX)) {
            log.info("从header里获取到的token为空或不符合规范");
            return null;
        }
        //解析Jwt字符串
        Claims claims = Jwts.parser()
                //验证秘钥
                .setSigningKey(jwtProperties.getSecret() + username)
                //验证对应的标准claim
                .requireSubject(username)
                .requireAudience(jwtProperties.getAud())
                .requireIssuer(jwtProperties.getIss())
                //验证jwt的唯一标识jti
                .requireId(jti)
                //获取声明信息
                .parseClaimsJws(token.replace(CommonDic.TOKEN_PREFIX, ""))
                .getBody();
        //获取UserDetailsInfo用户详细信息
        if (claims != null) {
            UserDetailsInfo detailsInfo = claims.get(CommonDic.USER_DETAILS_INFO, UserDetailsInfo.class);
            return detailsInfo;
        }
        return null;
    }


    /**
     * 获取jwt的唯一标识jti
     */
    public String getJti() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}
