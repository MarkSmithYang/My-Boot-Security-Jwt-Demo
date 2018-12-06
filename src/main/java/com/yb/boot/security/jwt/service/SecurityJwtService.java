package com.yb.boot.security.jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.common.CommonDic;
import com.yb.boot.security.jwt.exception.ParameterErrorException;
import com.yb.boot.security.jwt.repository.SysUserRepository;
import com.yb.boot.security.jwt.request.UserRequest;
import com.yb.boot.security.jwt.auth.other.CustomAuthenticationProvider;
import com.yb.boot.security.jwt.auth.other.MyUsernamePasswordAuthenticationToken;
import com.yb.boot.security.jwt.auth.tools.JwtTokenTools;
import com.yb.boot.security.jwt.common.JwtProperties;
import com.yb.boot.security.jwt.model.SysUser;
import com.yb.boot.security.jwt.model.UserInfo;
import com.yb.boot.security.jwt.response.JwtToken;
import com.yb.boot.security.jwt.response.UserDetailsInfo;
import com.yb.boot.security.jwt.utils.LoginUserUtils;
import com.yb.boot.security.jwt.utils.RealIpGetUtils;
import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

/**
 * Description:服务层代码
 * author yangbiao
 * date 2018/11/30
 */
@Service
public class SecurityJwtService {
    public static final Logger log = LoggerFactory.getLogger(SecurityJwtService.class);

    @Autowired
    private SysUserRepository sysUserRepository;
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    /**
     * 用户的登录认证
     */
    public JwtToken authUser(UserRequest userRequest, String from, HttpServletResponse response,
                             HttpServletRequest request) {
        //获取获取到的用户名和密码
        String username = userRequest.getUsername();
        String password = userRequest.getPassword();
        //构造Token类
        UsernamePasswordAuthenticationToken userToken = new MyUsernamePasswordAuthenticationToken(username, password, from);
        //调用自定义的用户认证Provider认证用户---(可以不使用自定义的这个认证,直接在过滤器那里处理--个人觉得)
        Authentication authenticate = customAuthenticationProvider.authenticate(userToken);
        //获取并解析封装在Authentication里的sysUser信息
        SysUser sysUser = JSONObject.parseObject((String) authenticate.getCredentials(), SysUser.class);
        //把认证信息存储安全上下文--(把密码等敏感信息置为null)
        authenticate = new UsernamePasswordAuthenticationToken(authenticate.getPrincipal(),
                null, authenticate.getAuthorities());
        //把构造的没有密码的信息放进安全上下文
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //封装sysUser到UserDetailsInfo
        if (sysUser == null) {
            log.info("sysUser通过密码参数传递过来解析出来为空");
            ParameterErrorException.message("用户名或密码错误");
        }
        //封装数据
        UserDetailsInfo detailsInfo = setUserDetailsInfo(sysUser, request);
        //生成token
        String accessToken = JwtTokenTools.createAccessToken(detailsInfo, jwtProperties.getExpireSeconds(), response,jwtProperties);
        String refreshToken = JwtTokenTools.createAccessToken(detailsInfo, jwtProperties.getExpireSeconds() * 7, response,jwtProperties);
        //封装token返回
        JwtToken jwtToken = new JwtToken();
        jwtToken.setAccessToken(CommonDic.TOKEN_PREFIX + accessToken);
        jwtToken.setRefreshToken(CommonDic.TOKEN_PREFIX + refreshToken);
        jwtToken.setTokenExpire(jwtProperties.getExpireSeconds());
        //填充数据到LoginUserUtils,供其他的子线程共享信息
        LoginUserUtils.setUserDetailsInfo(detailsInfo);
        //返回数据
        return jwtToken;
    }

    /**
     * 封装用户详情信息(角色权限部门电话等等信息)封装并存入redis里(from作为拼接的字符串)
     */
    public UserDetailsInfo setUserDetailsInfo(SysUser sysUser, HttpServletRequest request) {
        //实例化封装用户信息的类
        UserDetailsInfo detailsInfo = new UserDetailsInfo();
        //获取用户基本详细信息
        UserInfo userInfo = sysUser.getUserInfo();
        if (userInfo != null) {
            //封装用户基本详信息
            detailsInfo.setDepartment(userInfo.getDepartment());
            detailsInfo.setPhone(userInfo.getPhone());
            detailsInfo.setPosition(userInfo.getPosition());
        } else {
            log.info("用户的基本详细信息UserInfo信息为空");
        }
        //获取用户ip信息
        String ipAddress = RealIpGetUtils.getIpAddress(request);
        //封装用户基础信息
        detailsInfo.setId(sysUser.getId());
        detailsInfo.setCreateTime(sysUser.getCreateTime());
        detailsInfo.setHeadUrl(sysUser.getHeadUrl());
        detailsInfo.setUsername(sysUser.getUsername());
        detailsInfo.setIp(ipAddress);
        detailsInfo.setFrom(sysUser.getFrom());
        //获取权限角色的集合
        Set<String> permissions = detailsInfo.getPermissions();
        Set<String> roles = detailsInfo.getRoles();
        Set<String> modules = detailsInfo.getModules();
        //封装用户的权限角色信息
        if (CollectionUtils.isNotEmpty(sysUser.getPermissions())) {
            sysUser.getPermissions().forEach(s -> permissions.add(s.getPermission()));
        }
        //封装用户角色以及它的权限
        if (CollectionUtils.isNotEmpty(sysUser.getRoles())) {
            sysUser.getRoles().forEach(a -> {
                //封装角色信息
                roles.add(a.getRole());
                //封装角色的权限信息
                if (CollectionUtils.isNotEmpty(a.getPermissions())) {
                    a.getPermissions().forEach(d -> permissions.add(d.getPermission()));
                }
            });
        }
        //封装用户的模块以及它的权限
        if (CollectionUtils.isNotEmpty(sysUser.getModules())) {
            sysUser.getModules().forEach(f -> {
                //封装模块信息
                modules.add(f.getModule());
                //封装模块的权限信息
                if (CollectionUtils.isNotEmpty(f.getPermissions())) {
                    f.getPermissions().forEach(g -> permissions.add(g.getPermission()));
                }
            });
        }
        return detailsInfo;
    }
    //-------------------------------------------------------------------------------------------------------

}
