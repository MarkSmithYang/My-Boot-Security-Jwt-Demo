package com.yb.boot.security.jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.yb.boot.security.jwt.common.CommonDic;
import com.yb.boot.security.jwt.exception.ParameterErrorException;
import com.yb.boot.security.jwt.model.Permission;
import com.yb.boot.security.jwt.model.Role;
import com.yb.boot.security.jwt.repository.SysUserRepository;
import com.yb.boot.security.jwt.request.UserRegister;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
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
    private JwtProperties jwtProperties;
    @Autowired
    private SysUserRepository sysUserRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
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
        String accessToken = JwtTokenTools.createAccessToken(detailsInfo, jwtProperties.getExpireSeconds(), response, jwtProperties);
        String refreshToken = JwtTokenTools.createAccessToken(detailsInfo, jwtProperties.getExpireSeconds() * 7, response, jwtProperties);
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
        detailsInfo.setFrom(sysUser.getUserFrom());
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

    @Transactional(rollbackFor = Exception.class)
    public void addUser(UserRegister userRegister) {
        //校验密码与确认密码是否一致(虽然前段有做,但是后端必不可少才是正确的选择)
        if (!userRegister.checkPasswordEquals()) {
            ParameterErrorException.message("密码与确认密码不一致");
        }
        //封装用户基本信息--没有弄头像信息
        SysUser sysUser = new SysUser();
        sysUser.setUserFrom(userRegister.getFrom());
        sysUser.setUsername(userRegister.getUsername());
        //加密用户密码
        sysUser.setUserPassword(bCryptPasswordEncoder.encode(userRegister.getPassword()));
        //封装用户基础信息
        UserInfo userInfo = new UserInfo();
        userInfo.setDepartment(userRegister.getDepartment());
        userInfo.setPhone(userRegister.getPhone());
        userInfo.setPosition(userRegister.getPosition());
        //这一步特别重要,不做此步,userInfo的外键就是null(实测),先相互set的顺序并不影响添加
        //建议要保存的放在最后set其他的对象,如下sysUser-->实测只需只有id的对象即可,这样可以
        //减少封装,还可以避免反复嵌套让对象显得太笨重
        userInfo.setSysUser(new SysUser(sysUser.getId()));
        //把用户基础信息放进用户基本信息
        sysUser.setUserInfo(userInfo);
        //构造容器
        Set<Role> roleSet = new HashSet<>();
        Set<Permission> pSet1 = new HashSet<>();
        Set<Permission> pSet2 = new HashSet<>();
        //构造权限对象
        Permission permission1 = new Permission("pp1", "屁屁1");
        Permission permission2 = new Permission("pp2", "屁屁2");
        Permission permission3 = new Permission("pp3", "屁屁3");
        //添加一个权限到集合
        pSet2.add(permission1);
        //添加三个权限到集合
        ///pSet1.add(permission1);
        // 实测如果某权限有多个角色拥有,那么处理起来超级麻烦,因为同一个对象,你更改之后,
        //对象信息会被共享,也就是对象会以最后的修改为准,所以前后信息就会有问题,就会造成
        //某角色的权限的角色集合里处理这个角色对象之外,还有其他的角色对象在里面,这样的话
        //jpa(Hibernate)就会报错,说另一个对象的id找不到,因为它要通过id去查询并关联,目前
        //想到的唯一的办法就是先把含有相同权限的角色保存之后再关联另一个,可想这个得有多么繁复
        //所以还是那句话,尽量不要出现这种情况的设计,最好是角色不和权限关联,把角色假想成
        //多个细粒度的权限permission的集合,某个角色就含有那些权限(假想),可以添加描述角色的字段
        //可以更清楚知道角色假想的权限,这样不去实际关联权限,可以很大的减少其复杂度和提高性能和代码量
        //以及出错的风险-->同理模块与权限也是如此
        pSet1.add(permission2);
        pSet1.add(permission3);
        //构造角色对象信息并把对应的权限封装进去
        Role role1 = new Role("role1", "角色1", pSet2);
        //-----------------------------------------------------------------------------------------
        //角色对应权限需要封装其角色,为了生成中间表信息--当然了你如果知道了那些角色对应那些权限
        //可以先封装,个人角色这样遍历的方式比较好,既然知道了角色对应的权限,就可以开始封装关联了
        pSet2.forEach(s -> {
            //取出权限关联的角色集合,把新关联的角色添加进去即可
            Set<Role> roles = s.findRoles();
            roles.add(new Role(role1.getId()));
        });
        //注意--->当多个角色拥有相同的权限的时候,需要把多个角色封装到集合再和权限关联,不然就像我
        //这里一样遍历,就会把关联两个角色的权限里的角色id覆盖为最后的值,前面的就被覆盖了
        Role role2 = new Role("role2", "角色2", pSet1);
        //角色对应权限需要封装其角色,为了生成中间表信息
        pSet1.forEach(s -> {
            //因为集合在实体已经实例化了,所以取出来就可以直接使用
            //取出权限关联的角色集合,把新关联的角色添加进去即可
            Set<Role> roles = s.findRoles();
            //原本想在这通过获取权限是否含有角色来处理,但是不能提供对应的get方法,因为
            //如果提供的话,就会造成获取关联的数据的时候造成递归等json解析异常,所以把get
            //方法改了个名字就变成普通方法了,实测就不会出现问题了
            roles.add(new Role(role2.getId()));
        });
        //-----------------------------------------------------------------------------------------

        //封装sysUser信息,目的是为了生成中间表/外键信息
        role1.findUsers().add(new SysUser(sysUser.getId()));

        //这里应该是重写父类方法操作的多态(知道可以这样用,但是没仔细研究)
        role2.findUsers().add(new SysUser(sysUser.getId()));

        //把角色封装到集合roleSet再封装到sysUser
        roleSet.add(role1);
        roleSet.add(role2);
        sysUser.setRoles(roleSet);
        //保存用户信息---权限相关的信息,通过后面超管添加
        try {
            sysUserRepository.save(sysUser);
        } catch (Exception e) {
            try {
                sysUserRepository.save(sysUser);
            } catch (Exception e1) {
                log.info("用户信息第二次保存失败="+e1.getMessage());
                //抛出异常-->回滚事务
                ParameterErrorException.message("用户添加失败");
            }
        }
    }

}
