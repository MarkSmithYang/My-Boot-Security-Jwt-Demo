package com.yb.springsecurity.jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.auth.CustomAuthenticationProvider;
import com.yb.springsecurity.jwt.auth.MyUsernamePasswordAuthenticationToken;
import com.yb.springsecurity.jwt.common.CommonDic;
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
@RestController
public class SecurityJwtService {
    public static final Logger log = LoggerFactory.getLogger(SecurityJwtService.class);

    @Autowired
    private SysUserRepository sysUserRepository;
    @Autowired
    private RedisTemplate<String, Serializable> redisTemplate;

    /**
     * 用户的登录认证
     */
    public UserDetailsInfo authUser(SysUser sysUser, UserRequest userRequest, String from, CustomAuthenticationProvider
            customAuthenticationProvider, RedisTemplate<String, Serializable> redisTemplate) {
        //获取获取到的用户名和密码
        String username = userRequest.getUsername();
        String password = userRequest.getPassword();
        //构造Token类(自定义)
        UsernamePasswordAuthenticationToken userToken = new MyUsernamePasswordAuthenticationToken(username, password, from);
        //调用自定义的用户认证Provider认证用户
        Authentication authenticate = customAuthenticationProvider.authenticate(userToken);
        //把认证信息存储安全上下文
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //存储安全上下文信息到redis上(用SecurityContent的子类)
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authenticate);
        //生成token字符串并存储信息到redis
        String token = UUID.randomUUID().toString().replace("-", "");
        redisTemplate.opsForHash().put(token, CommonDic.SECURITY_CONTEXT, securityContext);
        //处理记住密码逻辑--->暂时还没理清
        if (userRequest.isRemember()) {
            //创建存储redis的key
            String retoken = CommonDic.REFRESH_TOKEN + UUID.randomUUID().toString();
            //存储信息到redis(就是延长用户这次输入的用户名密码的保存时间,下次登录在用这次输入的信息去登录)
            redisTemplate.opsForHash().put(retoken, CommonDic.USERNAME_PASSWORD_AUTHENTICATION_TOKEN, userRequest);
            //存储retoken字符串,方便下次获取用户登录的信息
            redisTemplate.opsForHash().put(token, CommonDic.REFRESH_TOKEN, retoken);
            //设置存储的过期时间(一周)
            redisTemplate.expire(retoken, CommonDic.RETOKEN_EXPIRE, TimeUnit.MINUTES);
        }
        //从redis获取用户详情信息
        UserDetailsInfo detailsInfo = (UserDetailsInfo) redisTemplate.opsForHash()
                .get(sysUser.getId() + from, CommonDic.USER_DETAILS_INFO);
        //返回数据
        return detailsInfo;
    }

    /**
     * 封装用户详情信息(角色权限部门电话等等信息)封装并存入redis里(from作为拼接的字符串)
     */
    public void setUserDetailsInfo(SysUser sysUser, String from) {
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
        //把用户详细信息存储到redis上
        redisTemplate.opsForHash().put(sysUser.getId() + from, CommonDic.USER_DETAILS_INFO, detailsInfo);
    }
    //-------------------------------------------------------------------------------------------------------

    /**
     * 通过用户名获取用户信息
     *
     * @param username
     * @return
     */
    public SysUser findByUsername(String username) {
        SysUser sysUser = sysUserRepository.findByUsername(username);
        return sysUser;
    }

}
