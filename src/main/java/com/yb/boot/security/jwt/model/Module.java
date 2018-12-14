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
 * Description:(菜单)模块类--主要是菜单模块分权
 * date 2018/11/30
 */
@Entity
@Table//这里就使用默认的映射策略
@ApiModel("模块类--主要是菜单模块分权")
public class Module implements Serializable {
    private static final long serialVersionUID = -3486259869151800327L;

    @Id//这个注解和@Table一样不能少@Column是可以少的
    private String id;

    /**
     * 模块
     */
    @ApiModelProperty("模块")
    @Column(unique = true)
    private String module;

    /**
     * 模块中文名
     */
    @ApiModelProperty("模块中文名")
    private String moduleCn;

    /**
     * 模块用户
     */
    @ApiModelProperty("模块用户")
    @ManyToMany(targetEntity = SysUser.class, fetch = FetchType.LAZY)
    private Set<SysUser> users= new HashSet<>();

    /**
     * 模块权限
     */
    @ApiModelProperty("模块权限")
    @ManyToMany(targetEntity = Permission.class, mappedBy = "modules", fetch = FetchType.EAGER)
    private Set<Permission> permissions= new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Module module1 = (Module) o;

        return new EqualsBuilder()
                .append(id, module1.id)
                .append(module, module1.module)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(id)
                .append(module)
                .toHashCode();
    }

    public Module() {
        this.id= UUID.randomUUID().toString().replaceAll("-", "");
    }

    public Module(String id) {
        this.id = id;
    }

    public Module(String module, String moduleCn, Set<SysUser> users, Set<Permission> permissions) {
        this.id= UUID.randomUUID().toString().replaceAll("-", "");
        this.module = module;
        this.moduleCn = moduleCn;
        this.users = users;
        this.permissions = permissions;
    }

    /**
     * 用以替代get方法获取数据,因为get方法会被jpa(Hibernate)用来获取关联对象的数据,
     * 会造成嵌套循环递归的获取数据而造成异常,所以只需要更换get方法名称即可,当然了
     * set方法也可以改名字,但是实测似乎不改也没什么问题,需要更改的是那种被获取的对象,
     * 例如sysUser获取Role,它们是多对多,我把Role看成相对多的一方,然后就需要更改Role里
     * 获取sysUser集合的get方法,因为sysUser获取角色集合后,角色再获取的用户的话,就会一直
     * 循环下去,知道堆栈溢出
     */
    public Set<SysUser> findUsers() {
        return users;
    }

    public void setUsers(Set<SysUser> users) {
        this.users = users;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public String getModuleCn() {
        return moduleCn;
    }

    public void setModuleCn(String moduleCn) {
        this.moduleCn = moduleCn;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }
}
