package com.yb.springsecurity.jwt.response;

import com.yb.springsecurity.jwt.model.SysUser;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * author yangbiao
 * Description:登录成功后返回的信息的封装类
 * date 2018/11/30
 */
@ApiModel("登录成功后返信息封装类")
public class Token implements Serializable{
    private static final long serialVersionUID = -5100113815346588190L;

    /**
     * 用户信息--我这里就只用基本信息了,如果需要用户的详细信息可以自己创建类去封装即可
     */
    @ApiModelProperty("用户信息")
    private SysUser sysUser;

    /**
     * 用户的角色信息
     */
    @ApiModelProperty("用户的角色信息")
    private Set<String> roles = new HashSet<>();

    /**
     * 用户的权限信息
     */
    @ApiModelProperty("用户的权限信息")
    private Set<String> permissions = new HashSet<>();

    /**
     * 用户的模块(菜单)信息
     */
    @ApiModelProperty("用户的模块(菜单)信息")
    private Set<String> modules = new HashSet<>();

    /**
     * 是否过期
     */
    @ApiModelProperty("是否过期")
    private boolean expired;

    /**
     * 是否是图片验证码
     */
    @ApiModelProperty("是否是图片验证码")
    private boolean isImgCode;

    /**
     * 是否是文本验证码
     */
    @ApiModelProperty("是否是文本验证码")
    private boolean isTextCode;

    /**
     * token的字符串
     */
    @ApiModelProperty("token的字符串")
    private String token;

    /**
     * 过期时间更长的token的字符串
     */
    @ApiModelProperty("过期时间更长的token的字符串")
    private String reToken;

    public SysUser getSysUser() {
        return sysUser;
    }

    public void setSysUser(SysUser sysUser) {
        this.sysUser = sysUser;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> getModules() {
        return modules;
    }

    public void setModules(Set<String> modules) {
        this.modules = modules;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public boolean isImgCode() {
        return isImgCode;
    }

    public void setImgCode(boolean imgCode) {
        isImgCode = imgCode;
    }

    public boolean isTextCode() {
        return isTextCode;
    }

    public void setTextCode(boolean textCode) {
        isTextCode = textCode;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getReToken() {
        return reToken;
    }

    public void setReToken(String reToken) {
        this.reToken = reToken;
    }
}
