package com.yb.springsecurity.jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.yb.springsecurity.jwt.auth.MyUsernamePasswordAuthenticationToken;
import com.yb.springsecurity.jwt.exception.ParameterErrorException;
import com.yb.springsecurity.jwt.model.Module;
import com.yb.springsecurity.jwt.model.Permission;
import com.yb.springsecurity.jwt.model.Role;
import com.yb.springsecurity.jwt.model.SysUser;
import com.yb.springsecurity.jwt.repository.SysUserRepository;
import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String auth) throws UsernameNotFoundException {
        //解析json字符串
        Authentication authentication = JSONObject.parseObject(auth, Authentication.class);
        //获取需要认证的用户名
        String username = (String) authentication.getPrincipal();
        //获取需要认证的密码
        String password = authentication.getCredentials().toString();
        //获取from因为new MyUsernamePasswordAuthenticationToken传递进来的,不用判断所属也可以直接强转的
        String from = ((MyUsernamePasswordAuthenticationToken) authentication).getFrom();
        //进行自定义的逻辑认证--(如果用户名可能是电话号码,邮箱地址,用户名,这个需要逐个去查询判断)
        SysUser sysUser = sysUserRepository.findByUsernameAndFrom(username, from);
        //判断用户名是否正确
        if (sysUser == null) {
            ParameterErrorException.message("用户名或密码错误");
        }
        //判断用户密码是否正确
        if (!bCryptPasswordEncoder.matches(password, sysUser.getPassword())) {
            ParameterErrorException.message("用户名或密码错误");
        }
        //封装数据到UserDetailsli
        if (sysUser == null) {
            log.info("通过用户名查询出来的用户的id去查询用户信息为空(数据前后有改动)");
            ParameterErrorException.message("用户名或密码错误");
            //一般不会为空,因为前面都能查询到(除非数据库在期间被动过或现在的查询异常了)
            return null;
        }
        //实例化一个装权限的集合类型为GranteAuthority-->因为判断的时候是通过这个权限来判断的,
        // 所以当你不添加角色和模块名去构造对象,就相当于找不到匹配的角色或模块了
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
                //封装角色
                authorities.add(new SimpleGrantedAuthority(s.getRole()));
                //封装角色权限
                if (CollectionUtils.isNotEmpty(s.getPermissions())) {
                    //我这里没有写实现类来封装直接用了lambda表达式做的实现-->我这类没有用对象的id,
                    //而是直接用权限(set集合去重),需要重写equals和hashCode
                    s.getPermissions().forEach(a ->
                            authorities.add(new SimpleGrantedAuthority(a.getPermission())));
                }
            });
        }
        //获取用户模块(菜单)
        Set<Module> modules = sysUser.getModules();
        //获取模块的权限并添加到authorities
        if (CollectionUtils.isNotEmpty(modules)) {
            modules.forEach(s -> {
                //添加模块到authorities
                authorities.add(new SimpleGrantedAuthority(s.getModule()));
                //添加模块权限到auhorities
                if (CollectionUtils.isNotEmpty(s.getPermissions())) {
                    s.getPermissions().forEach(a -> {
                        authorities.add(new SimpleGrantedAuthority(a.getPermission()));
                    });
                }
            });
        }
        //this(username, password, true, true, true, true, authorities);
        //如果有需要可以在这里设置账户的锁定等信息,设置对应的true和false来获取判断即可
        //这里用了security实现了UserDetails的User没有自己来实现UserDetails来自定义接口扩展内容,
        //可以通过@JsonIgnore(对应实现的方法上)屏蔽掉想要屏蔽的信息,屏蔽密码,置为null
        //密码设置为空,还不如用来传递sysUser,省得再去查询数据库获取数据封装UserDetailsInfo
        String strSysUser = JSONObject.toJSON(sysUser).toString();
        return new User(sysUser.getUsername(), strSysUser, authorities);
    }

}

