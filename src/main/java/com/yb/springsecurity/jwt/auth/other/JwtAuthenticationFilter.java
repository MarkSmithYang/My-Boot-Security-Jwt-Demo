package com.yb.springsecurity.jwt.auth.other;

import com.yb.springsecurity.jwt.auth.tools.JwtTokenTools;
import com.yb.springsecurity.jwt.common.CommonDic;
import com.yb.springsecurity.jwt.common.JwtProperties;
import com.yb.springsecurity.jwt.response.UserDetailsInfo;
import com.yb.springsecurity.jwt.utils.LoginUserUtils;
import com.yb.springsecurity.jwt.utils.RealIpGetUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * author yangbiao
 * Description:验证其他请求token是否合法的类 OncePerRequestFilter继承GenericFilterBean了, 并扩展了内容
 * date 2018/11/30
 */
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtProperties jwtProperties;

    /**
     * 判断带jwt的请求token的合法性
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        //获取请求头里的token值
        String token = request.getHeader(CommonDic.HEADER_SINGLE);
        //判断token是否为空
        if (StringUtils.isBlank(token) || !token.startsWith(CommonDic.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            //结束方法
            return;
        }
        //解析jwt
        UserDetailsInfo detailsInfo = JwtTokenTools.getUserByJwt(token, jwtProperties);
        //判断解析出的对象
        if (detailsInfo == null) {
            chain.doFilter(request, response);
            return;
        }
        //更新用户ip信息(一般也没必要这么做)
        detailsInfo.setIp(RealIpGetUtils.getIpAddress(request));
        //把用户详细信息放到(更新到)LoginUserUtils
        LoginUserUtils.setUserDetailsInfo(detailsInfo);
        //获取封装用户的角色权限模块等信息---注意这里有个坑,角色名和权限名和模块名不要重复,
        //不然会造成权限混乱,事实上角色和模块也是种权限(包含了一堆权限的权限),所以统一加前缀
        //去区分,在接口方法上使用注解哪里也要加同样的前缀才能匹配到
        //根据自己的需要可以进行封装城工具使用,减少代码重复
        Set<GrantedAuthority> authorities = new HashSet<>();
        //封装用户权限信息,detailsInfo里面的权限角色模块全都分离处理过的,所以可以直接用
        if (CollectionUtils.isNotEmpty(detailsInfo.getPermissions())) {
            Set<SimpleGrantedAuthority> collect = detailsInfo.getPermissions().stream().map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            //合并集合数据
            authorities.addAll(collect);
        }
        //封装用户角色信息
        if (CollectionUtils.isNotEmpty(detailsInfo.getRoles())) {
            Set<SimpleGrantedAuthority> collect = detailsInfo.getRoles().stream().map(s -> {
                return new SimpleGrantedAuthority(CommonDic.ROLES_ + s);}).collect(Collectors.toSet());
            //合并集合数据
            authorities.addAll(collect);
        }
        //封装用户模块信息
        if (CollectionUtils.isNotEmpty(detailsInfo.getModules())) {
            Set<SimpleGrantedAuthority> collect = detailsInfo.getModules().stream().map(a->{
                return new SimpleGrantedAuthority(CommonDic.MODULES_+a);}).collect(Collectors.toSet());
            //合并集合数据
            authorities.addAll(collect);
        }
        //把认证信息存储安全上下文--(把密码等敏感信息置为null)
        Authentication authenticate = new UsernamePasswordAuthenticationToken(detailsInfo.getUsername(),
                null, authorities);
        //把构造的没有密码的信息放进安全上下文
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //执行过滤
        chain.doFilter(request, response);
    }

}
