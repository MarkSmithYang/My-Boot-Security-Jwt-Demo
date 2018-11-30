package com.yb.springsecurity.jwt.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

/**
 * author yangbiao
 * Description:系统用户-->用户信息-->这里全部笼统的放置用户信息了
 * date 2018/11/30
 */
@Entity
@Table//这里就使用默认的映射策略
@ApiModel("基础用户信息类")
public class SysUser implements Serializable {
    private static final long serialVersionUID = -4454755005986723821L;

    @Id//这个注解和@Table一样不能少@Column是可以少的
    private String id;

    /**
     * 用户名
     */
    @ApiModelProperty("用户名")
    @Column(unique = true)
    private String username;

    /**
     * 密码
     */
    @JsonIgnore
    @ApiModelProperty("密码")
    private String password;

    /**
     * 头像信息
     */
    @ApiModelProperty("头像信息")
    private String headUrl;

    /**
     * 用户来源--前台/后台/app等
     */
    @ApiModelProperty("头像信息")
    private String from;

    /**
     * 创建时间
     */
    @ApiModelProperty("创建时间")
    private LocalDateTime createTime;

    @ApiModelProperty("用户基本详细信息")
    @OneToOne(targetEntity =UserInfo.class,mappedBy = "sysUser",fetch = FetchType.EAGER)
    private UserInfo userInfo;

    /**
     * 用户模块(用户可以访问的菜单(模块),这个是另一种授权方式)
     */
    @ApiModelProperty("用户模块")
    @ManyToMany(targetEntity = Module.class, mappedBy = "users", fetch = FetchType.EAGER)
    private Set<Module> modules;

    /**
     * 用户权限
     */
    @ApiModelProperty("用户权限")
    @ManyToMany(targetEntity = Permission.class, mappedBy = "users", fetch = FetchType.EAGER)
    private Set<Permission> permissions;

    /**
     * 用户角色
     */
    @ApiModelProperty("用户角色")
    @ManyToMany(targetEntity = Role.class,mappedBy = "users", fetch = FetchType.EAGER)
    private Set<Role> roles;

    public SysUser() {
        this.id = UUID.randomUUID().toString().replaceAll("-", "");
        this.createTime = LocalDateTime.now();
    }

    public SysUser(String username, String password) {
        this.id = UUID.randomUUID().toString().replaceAll("-", "");
        this.username = username;
        this.password = password;
        this.createTime = LocalDateTime.now();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        SysUser sysUser = (SysUser) o;

        return new EqualsBuilder()
                .append(id, sysUser.id)
                .append(username, sysUser.username)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(id)
                .append(username)
                .toHashCode();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public LocalDateTime getCreateTime() {
        return createTime;
    }

    public void setCreateTime(LocalDateTime createTime) {
        this.createTime = createTime;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public String getHeadUrl() {
        return headUrl;
    }

    public void setHeadUrl(String headUrl) {
        this.headUrl = headUrl;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    public Set<Module> getModules() {
        return modules;
    }

    public void setModules(Set<Module> modules) {
        this.modules = modules;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }
}
