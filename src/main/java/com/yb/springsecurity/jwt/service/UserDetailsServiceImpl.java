package com.yb.springsecurity.jwt.service;

import com.yb.springsecurity.jwt.exception.ParameterErrorException;
import com.yb.springsecurity.jwt.model.Permission;
import com.yb.springsecurity.jwt.model.Role;
import com.yb.springsecurity.jwt.model.SysUser;
import com.yb.springsecurity.jwt.repository.SysUserRepository;
import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Description:UserDetailsService接口的实现类
 * author yangbiao
 * date 2018/11/30
 */
@Component
public class UserDetailsServiceImpl implements UserDetailsService {
    public static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    private SysUserRepository sysUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = sysUserRepository.findByUsername(username);
        if (sysUser == null) {
            return null;
        } else {
            return loadUserById(sysUser.getId());
        }
    }

    /**
     * 通过id查询用户信息
     *
     * @param id
     * @return
     */
    public UserDetails loadUserById(String id) {
        SysUser sysUser = sysUserRepository.findById(id).isPresent() ? sysUserRepository.findById(id).get() : null;
        if (sysUser == null) {
            log.info("通过用户名查询出来的用户的id去查询用户信息为空(数据前后有改动)");
            ParameterErrorException.message("用户名或密码错误");
        }
        //实例化一个装权限的集合类型为GranteAuthority
        List<GrantedAuthority> authorities = new ArrayList<>();
        //获取用户权限
        Set<Permission> permissions = sysUser.getPermissions();
        //遍历获取权限添加到authorities
        if (CollectionUtils.isNotEmpty(permissions)) {
            //我这里没有写实现类来封装直接用了lambda表达式做的实现-->我这类没有用对象的id,
            // 而是直接用权限(set集合去重),需要重写equals和hashCode
            permissions.forEach(s ->
                    authorities.add(new SimpleGrantedAuthority(s.getPermission())));
        }
        //获取用户角色
        Set<Role> roles = sysUser.getRoles();
        //获取角色拥有的权限添加到authorities
        if (CollectionUtils.isNotEmpty(roles)) {
            roles.forEach(s -> {
                if (CollectionUtils.isNotEmpty(s.getPermissions())) {
                    //我这里没有写实现类来封装直接用了lambda表达式做的实现-->我这类没有用对象的id,
                    //而是直接用权限(set集合去重),需要重写equals和hashCode
                    s.getPermissions().forEach(a ->
                            authorities.add(new SimpleGrantedAuthority(a.getPermission())));
                }
            });
        }
        //this(username, password, true, true, true, true, authorities);
        //如果有需要可以在这里设置账户的锁定等信息
        //这里用了security实现了UserDetails的User没有自己来实现UserDetails来自定义接口扩展内容
        return new User(sysUser.getUsername(), sysUser.getPassword(), authorities);
    }
}

