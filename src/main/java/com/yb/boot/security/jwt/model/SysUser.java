package com.yb.boot.security.jwt.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
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
    private String userPassword;

    /**
     * 头像信息
     */
    @ApiModelProperty("头像信息")
    private String headUrl;

    /**
     * 用户来源--前台/后台/app等
     */
    @ApiModelProperty("头像信息")
    private String userFrom;

    /**
     * 创建时间
     */
    @ApiModelProperty("创建时间")
    private LocalDateTime createTime;

    @ApiModelProperty("用户基本详细信息")
    @OneToOne(targetEntity = UserInfo.class, mappedBy = "sysUser", fetch = FetchType.EAGER,
            //注意级联的设置需要放在保存的那个实体里设置,例如我保存sysUser级联保存userInfo,那么
            //我就在sysUser里的这里设置级联操作,但是如果在userInfo里设置,userInfo的信息就不会添加成功(实测)
            //虽然sysUser不是主控方,但是依旧可以这样保存成功,刚才一直没有保存成功是因为属性设置生成的数据库表
            //字段是mysql的关键字,例如from和password,所以一直报sql错误,找了半天,最后把映射改了之后就可以了
            //实测,当没有设置级联操作的时候,userInfo是没法添加信息的
            cascade = CascadeType.ALL)
    private UserInfo userInfo;

    /**
     * 用户模块(用户可以访问的菜单(模块),这个是另一种授权方式)
     */
    @ApiModelProperty("用户模块")
    @ManyToMany(targetEntity = Module.class, mappedBy = "users", fetch = FetchType.EAGER)
    private Set<Module> modules= new HashSet<>();

    /**
     * 用户权限
     */
    @ApiModelProperty("用户权限")
    @ManyToMany(targetEntity = Permission.class, mappedBy = "users", fetch = FetchType.EAGER)
    private Set<Permission> permissions= new HashSet<>();

    /**
     * 用户角色
     */
    @ApiModelProperty("用户角色")
    @ManyToMany(targetEntity = Role.class, mappedBy = "users", fetch = FetchType.EAGER,
            //实测像这样的多对多级联保存和一对一差不多,但是如果不设置级联操作,就是保存角色,就会报错(实测)
            //但是虽然角色能成功添加,但是用户和角色关联的中间表信息却没有添加,这个获取就和一对一一样了,需要相互set
            //也就是需要把sysUser放进Role里去才行,每个role都需要这样做才对,因为sysUser有关联的主键信息,因为我这里
            //是保存一个sysUser保存多个Role(一般都是这样的,当然了有保存用户集合的情况),所以添加的时候为
            //role2.setUsers(new HashSet<SysUser>(){{add(sysUser);}});这样的,具体根据实际情况添加sysUser到
            //集合再set即可,注意每个角色关联与否(能否需要生成相关联的中间表的信息,就需要自己来添加,一般来说都是需要的)
            //注意,这里角色的权限没有做添加,如果添加需要在角色里添加级联权限的操作(实测如果没有设置就添加就会报错),
            //和sysUsery与Role的做法相似
            cascade = CascadeType.ALL)
    private Set<Role> roles= new HashSet<>();

    public SysUser() {
        this.id = UUID.randomUUID().toString().replaceAll("-", "");
        this.createTime = LocalDateTime.now();
    }

    public SysUser(String id) {
        this.id = id;
    }

    public SysUser(String username, String userPassword) {
        this.id = UUID.randomUUID().toString().replaceAll("-", "");
        this.username = username;
        this.userPassword = userPassword;
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

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getUserFrom() {
        return userFrom;
    }

    public void setUserFrom(String userFrom) {
        this.userFrom = userFrom;
    }
}
