package com.yb.springsecurity.jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.auth.CustomAuthenticationProvider;
import com.yb.springsecurity.jwt.auth.MyUsernamePasswordAuthenticationToken;
import com.yb.springsecurity.jwt.auth.tools.JwtTokenTools;
import com.yb.springsecurity.jwt.common.CommonDic;
import com.yb.springsecurity.jwt.exception.ParameterErrorException;
import com.yb.springsecurity.jwt.model.SysUser;
import com.yb.springsecurity.jwt.model.UserInfo;
import com.yb.springsecurity.jwt.repository.SysUserRepository;
import com.yb.springsecurity.jwt.request.UserRequest;
import com.yb.springsecurity.jwt.response.UserDetailsInfo;
import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

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
    private JwtTokenTools jwtTokenTools;
    @Autowired
    private RedisTemplate<String, Serializable> redisTemplate;
    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    /**
     * 用户的登录认证
     */
    public String  authUser(UserRequest userRequest, String from, HttpServletResponse response) {
        //获取获取到的用户名和密码
        String username = userRequest.getUsername();
        String password = userRequest.getPassword();
        //构造Token类
        UsernamePasswordAuthenticationToken userToken = new MyUsernamePasswordAuthenticationToken(username, password, from);
        //调用自定义的用户认证Provider认证用户---(可以不使用自定义的这个认证,直接在过滤器那里处理--个人觉得)
        Authentication authenticate = customAuthenticationProvider.authenticate(userToken);
        //把认证信息存储安全上下文
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //获取并解析封装在Authentication里的sysUser信息
        SysUser sysUser = JSONObject.parseObject((String) authenticate.getCredentials(), SysUser.class);
        //封装sysUser到UserDetailsInfo
        if(sysUser==null){
            log.info("sysUser通过密码参数传递过来解析出来为空");
            ParameterErrorException.message("用户名或密码错误");
        }
        //封装数据
        UserDetailsInfo detailsInfo = setUserDetailsInfo(sysUser);
        //把用户详细信息写入到jwt中
        String accessToken = jwtTokenTools.createAccessToken(detailsInfo, response);
        //返回数据
        return accessToken;
    }

    /**
     * 封装用户详情信息(角色权限部门电话等等信息)封装并存入redis里(from作为拼接的字符串)
     */
    public UserDetailsInfo setUserDetailsInfo(SysUser sysUser) {
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
        //封装用户基础信息
        detailsInfo.setId(sysUser.getId());
        detailsInfo.setCreateTime(sysUser.getCreateTime());
        detailsInfo.setHeadUrl(sysUser.getHeadUrl());
        detailsInfo.setUsername(sysUser.getUsername());
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
        //把用户详细信息存储到redis上
//        redisTemplate.opsForHash().put(sysUser.getId() + sysUser.getFrom(), CommonDic.USER_DETAILS_INFO, detailsInfo);
    }
    //-------------------------------------------------------------------------------------------------------

    /**
     * 通过用户名和用户来源获取用户信息
     */
    public SysUser findByUsernameAndFrom(String username, String from) {
        SysUser sysUser = sysUserRepository.findByUsernameAndFrom(username, from);
        return sysUser;
    }
}
