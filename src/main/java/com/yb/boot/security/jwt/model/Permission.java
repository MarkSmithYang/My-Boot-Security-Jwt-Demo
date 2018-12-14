package com.yb.boot.security.jwt.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * author yangbiao
 * Description:权限信息类
 * date 2018/11/30
 */
@Entity
@Table//这里就使用默认的映射策略
@ApiModel("权限信息类")
public class Permission implements Serializable {
    private static final long serialVersionUID = -5566183753194600505L;

    @Id//这个注解和@Table一样不能少@Column是可以少的
    private String id;

    /**
     * 权限
     */
    @Column(unique = true)
    @ApiModelProperty("权限")
    private String permission;

    /**
     * 权限中文
     */
    @ApiModelProperty("权限中文")
    private String permissionCn;

    /**
     * 权限角色
     */
    @ApiModelProperty("权限角色")
    @ManyToMany(targetEntity = Role.class,fetch = FetchType.LAZY)
    private Set<Role> roles  = new HashSet<>();

    /**
     * 权限用户
     */
    @ApiModelProperty("权限用户")
    @ManyToMany(targetEntity = SysUser.class,fetch = FetchType.LAZY)
    private Set<SysUser> users= new HashSet<>();

    /**
     * 权限模块
     */
    @ApiModelProperty("权限模块")
    @ManyToMany(targetEntity = Module.class,fetch = FetchType.LAZY)
    private Set<Module> modules= new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Permission that = (Permission) o;

        return new EqualsBuilder()
                .append(id, that.id)
                .append(permission, that.permission)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(id)
                .append(permission)
                .toHashCode();
    }

    public Permission() {
        this.id= UUID.randomUUID().toString().replaceAll("-", "");
    }

    public Permission(String id) {
        this.id = id;
    }

    public Permission(String permission, String permissionCn) {
        this.permission = permission;
        this.permissionCn = permissionCn;
        this.id= UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 用以替代get方法获取数据,因为get方法会被jpa(Hibernate)用来获取关联对象的数据,
     * 会造成嵌套循环递归的获取数据而造成异常,所以只需要更换get方法名称即可,当然了
     * set方法也可以改名字,但是实测似乎不改也没什么问题,需要更改的是那种被获取的对象,
     * 例如sysUser获取Role,它们是多对多,我把Role看成相对多的一方,然后就需要更改Role里
     * 获取sysUser集合的get方法,因为sysUser获取角色集合后,角色再获取的用户的话,就会一直
     * 循环下去,知道堆栈溢出
     */
    public Set<Role> findRoles() {
        return roles;
    }

    public Set<SysUser> findUsers() {
        return users;
    }

    public Set<Module> findModules() {
        return modules;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void setUsers(Set<SysUser> users) {
        this.users = users;
    }

    public void setModules(Set<Module> modules) {
        this.modules = modules;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public String getPermissionCn() {
        return permissionCn;
    }

    public void setPermissionCn(String permissionCn) {
        this.permissionCn = permissionCn;
    }

}
