package com.yb.boot.security.jwt.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import javax.persistence.*;
import java.io.Serializable;
import java.util.Set;

/**
 * author yangbiao
 * Description:角色信息表
 * date 2018/11/30
 */
@Entity
@Table//这里就使用默认的映射策略
@ApiModel("角色信息表")
public class Role implements Serializable {
    private static final long serialVersionUID = -1424025425731168559L;

    @Id//这个注解和@Table一样不能少@Column是可以少的
    private String id;

    /**
     * 角色
     */
    @ApiModelProperty("角色")
    @Column(unique = true)
    private String role;

    /**
     * 角色中文
     */
    @ApiModelProperty("角色中文")
    private String roleCn;

    /**
     * 角色权限
     */
    @ApiModelProperty("角色权限")
    @ManyToMany(targetEntity = Permission.class,mappedBy = "roles",fetch = FetchType.EAGER)
    private Set<Permission> permissions;

    /**
     * 角色用户
     */
    @ApiModelProperty("角色用户")
    @ManyToMany(targetEntity = SysUser.class, fetch = FetchType.LAZY)
    private Set<SysUser> users;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        Role role1 = (Role) o;

        return new EqualsBuilder()
                .append(id, role1.id)
                .append(role, role1.role)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(id)
                .append(role)
                .toHashCode();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getRoleCn() {
        return roleCn;
    }

    public void setRoleCn(String roleCn) {
        this.roleCn = roleCn;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }
}
