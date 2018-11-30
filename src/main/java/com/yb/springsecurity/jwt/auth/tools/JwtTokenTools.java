package com.yb.springsecurity.jwt.auth.tools;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.common.ResultInfo;
import com.yb.springsecurity.jwt.response.UserDetailsInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Description:Jwt的token工具
 * author yangbiao
 * date 2018/11/30
 */
public class JwtTokenTools {
    public static final Logger log = LoggerFactory.getLogger(JwtTokenTools.class);

    public static final long TOKEN_EXPIRATION_TIME = 30 * 60 * 1000;//60分钟的过期时间
    public static final String TOKEN_PREFIX = "Bearer ";//token的前缀
    public static final String HEADER_SINGLE = "Authorization";//请求头Header的token的key

    /**
     * 生成token令牌(到body)
     */
    public static String createAccessToken(UserDetailsInfo detailsInfo,String jti) {
        //创建jwt(token)
        String token = Jwts.builder()
                //说明类型为JWT(签名算法就不说了,怕与下面的冲突)
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS512")
                //签发者设置--------->claim部分
                .claim("userId", "1111")
                .setIssuer("yb")
                //接收jwt的一方(观众)
                .setAudience("gateway")
                //jwt(token)所面向的用户(一般都是用户名)
                .setSubject("jack")
                //设置jwt(token)的过期时间
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
                //设置jwt(token)的签发时间
                .setIssuedAt(new Date())
                //设置在什么时间之前token不可用
//                .setNotBefore(new Date(System.currentTimeMillis()))
                //设置jwt(token)的唯一标识jti
                .setId("1")
                //签名设置--(设置加密算法)-------->签名部分
                .signWith(SignatureAlgorithm.HS512, "12345")
                //这个是全部设置完成后拼成jwt串的方法
                .compact();
        return token;
    }

    public static String createToken(){
        //创建jwt(token)
        String token = Jwts.builder()
                //说明类型为JWT(签名算法就不说了,怕与下面的冲突)
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS512")
                //签发者设置--------->claim部分
                .claim("userId", "1111")
                .setIssuer("")
                //接收jwt的一方(观众)
                .setAudience("gateway")
                //jwt(token)所面向的用户(一般都是用户名)
                .setSubject("jack")
                //设置jwt(token)的过期时间
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
                //设置jwt(token)的签发时间
                .setIssuedAt(new Date())
                //设置在什么时间之前token不可用
//                .setNotBefore(new Date(System.currentTimeMillis()))
                //设置jwt(token)的唯一标识jti
                .setId("1")
                //签名设置--(设置加密算法)-------->签名部分
                .signWith(SignatureAlgorithm.HS512, "12345")
                //这个是全部设置完成后拼成jwt串的方法
                .compact();
        return token;
    }


    /**
     * 获取jwt的唯一标识jti
     *
     * @return
     */
    public String getJti() {
        return UUID.randomUUID().toString().replace("-", "");
    }


    public static Claims parseJwt(String jwtToken){
        Claims claims = Jwts.parser()
                .setSigningKey("a")
                .parseClaimsJwt(jwtToken)
                .getBody();
        return claims;
    }

    public static String create1(){
        return Jwts.builder()
                .setSubject("aa")
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, "aaaaaa").compact();
    }
    public static void main(String[] args) {
        String a = create1();
        Claims claims = parseJwt(a);
        if(claims!=null){
            String subject = claims.getSubject();
            System.err.println(subject);
        }
    }
}
