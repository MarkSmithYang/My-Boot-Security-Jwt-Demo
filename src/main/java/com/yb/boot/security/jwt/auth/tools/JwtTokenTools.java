package com.yb.boot.security.jwt.auth.tools;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.common.CommonDic;
import com.yb.boot.security.jwt.common.JwtProperties;
import com.yb.boot.security.jwt.exception.ParameterErrorException;
import com.yb.boot.security.jwt.response.UserDetailsInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.util.*;

/**
 * Description:Jwt的token工具
 * author yangbiao
 * date 2018/11/30
 */
public class JwtTokenTools {
 public static final Logger log = LoggerFactory.getLogger(JwtTokenTools.class);


    /**
     * 生成jwt令牌
     */
    public static String createAccessToken(UserDetailsInfo detailsInfo, int expireTime,
                                           HttpServletResponse response, JwtProperties jwtProperties) {
        //判断用户信息
        if(detailsInfo==null){
            log.info("用于生成jwt的用户信息为null");
            return null;
        }
        //创建jwt(token)
        String token = Jwts.builder()
                //说明类型为JWT(签名算法就不说了,怕与下面的冲突)
                .setHeaderParam("typ", "JWT")
                //签发者设置--------->claim部分--这样单独封装属性,对后面的解析转换处理会更方便
                //因为日期时间在这里封装之后,没法解析出来(因为会变成一个map),所以我这里就不封装了
                //如果需要用到用户账户的创建时间,通过获取用户的id去数据库获取即可,一般很少用到那个的
                .claim("id", detailsInfo.getId())
                .claim("username", detailsInfo.getUsername())
                .claim("headUrl", detailsInfo.getHeadUrl())
                .claim("department", detailsInfo.getDepartment())
                .claim("position", detailsInfo.getPosition())
                .claim("phone", detailsInfo.getPhone())
                .claim("ip", detailsInfo.getIp())
                .claim("from", detailsInfo.getFrom())
                .claim("permissions", detailsInfo.getPermissions())
                .claim("roles", detailsInfo.getRoles())
                .claim("modules", detailsInfo.getModules())
                //设置发布人
                .setIssuer(jwtProperties.getIss())
                //接收jwt的一方(观众)
                .setAudience(jwtProperties.getAud())
                //jwt(token)所面向的用户(一般都是用户名)
                .setSubject(detailsInfo.getUsername())
                //设置jwt(token)的过期时间(因为过期时间是当前获取的时间加上固定设置的时间,所以肯定未来才过期)
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                //设置jwt(token)的签发时间--->因为parse的时候没法指定时间,所以觉得设置了也什么用
                .setIssuedAt(new Date())//-----可有可无的设置
                //设置在什么时间之前token不可用--->因为parse的时候没法指定时间,所以觉得设置了也什么用
                .setNotBefore(new Date(System.currentTimeMillis()))//-----可有可无的设置
                //设置jwt(token)的唯一标识jti-->这个用处并不是很大了,因为过滤处理的时候没法获取到用户的jti
                //这部分的内容我删除了,因为如果解析的时候没法验证,这里也没什么太大的意义,而且我还要去redis存储
                //.setId(jti)//-----可有可无的设置
                //签名设置--(设置加密算法)-------->签名部分
                .signWith(SignatureAlgorithm.HS512, DatatypeConverter.parseBase64Binary(jwtProperties.getSecret()))
                //这个是全部设置完成后拼成jwt串的方法
                .compact();
        //把jwt写入header--(相对重要的一步)
        response.setHeader(CommonDic.HEADER_SINGLE, CommonDic.TOKEN_PREFIX + token);
        //返回jwt字符串
        return token;
    }

    /**
     * 解析Jwt字符串--因为再过滤器那里没法获取用户名,所以这里subject和jti就没去验证了
     * 而且由此可以看出jti用处显然没了
     */
    public static Claims parseJwt(String token, JwtProperties jwtProperties) {
        //解析Jwt字符串
        Claims claims = Jwts.parser()
                //验证秘钥--秘钥需和生成jwt的秘钥完全保持一致
                //(本人觉得这里它肯定通过某种方式知道其加密算法,或者根本不需要知道加密算法)
                .setSigningKey(DatatypeConverter.parseBase64Binary(jwtProperties.getSecret()))
                //验证对应的标准claim
                .requireAudience(jwtProperties.getAud())//不要可以的仅仅只是多验证点东西而已
                .requireIssuer(jwtProperties.getIss())//不要可以的仅仅只是多验证点东西而已
                //获取声明信息
                .parseClaimsJws(token.replace(CommonDic.TOKEN_PREFIX, ""))
                .getBody();
        return claims;
    }

    /**
     * 通过合法的jwt获取用户信息
     */
    public static UserDetailsInfo getUserByJwt(String token, JwtProperties jwtProperties) {
        if (StringUtils.isNotBlank(token) && token.startsWith(CommonDic.TOKEN_PREFIX)) {
            //验证jwt合法性--(因为如果直接切割获取中间那段解析,如果没有改变中间那段,
            //实测在token后面随便加点字符都能通过认证,这个应该是不能允许的,实测加了
            //这段解析验证的代码,就没法通过了,jwt需要用秘钥验证,没被篡改过才能通过
            JwtTokenTools.parseJwt(token, jwtProperties);
            //判断jwt合法之后再处理信息,这里实测是通过抛SignatureException异常来中断程序的,
            //接口哪里提示请登录,其实parseJwt如果没有特别需要获取claim里的东西,可以不用返回的
            if (!token.contains(".")) {
                ParameterErrorException.message("无效的token信息");
            }
            //解析jwt并获取用户详细信息
            String[] split = token.split("\\.");
            //如果token切割的split数组长度不为3,说明token不正确(防止抛出异常)
            String claims = new String(Base64Utils.decodeFromUrlSafeString(split.length == 3 ? split[1] : ""));
            //解析字符串获取用户详细信息对象
            UserDetailsInfo detailsInfo = JSONObject.parseObject(claims, UserDetailsInfo.class);
            return detailsInfo;
        }
        return null;
    }

    /**
     * 获取jwt的唯一标识jti---这个我没有使用了,因为parse的时候,没法获取用户关联的jti,
     * 所以个人觉得写入jwt也没太大的意义
     */
    public static String getJti() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}
