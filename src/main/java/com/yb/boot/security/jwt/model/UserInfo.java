package com.yb.boot.security.jwt.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * Description:用户基本详细信息(根据自己的实际情况封装)
 * author yangbiao
 * date 2018/11/26
 */
@Entity
@Table
@ApiModel("用户基本详细信息")
public class UserInfo implements Serializable {
    private static final long serialVersionUID = -5866848556563329530L;

    @Id
    @ApiModelProperty("id")
    private String id;

    @ApiModelProperty("用户部门")
    private String department;

    @ApiModelProperty("用户职位")
    private String position;

    @ApiModelProperty("用户电话")
    private String phone;

    //外键由没有写mappyed的一方维护,建表的时候会多生成一个外键,
    //直接用这个题是没法封装数据的,因为少了一个属性去封装外键,
    //当了可以直接用SysUser直接get获取
    @ApiModelProperty("基础用户信息")
    @OneToOne(targetEntity = SysUser.class)
    private SysUser sysUser;

    public UserInfo() {
        this.id = UUID.randomUUID().toString().replaceAll("-", "");
    }

    public UserInfo(String id) {
        this.id = id;
    }

    /**
     * 用以替代get方法获取数据,因为get方法会被jpa(Hibernate)用来获取关联对象的数据,
     * 会造成嵌套循环递归的获取数据而造成异常,所以只需要更换get方法名称即可,当然了
     * set方法也可以改名字,但是实测似乎不改也没什么问题,需要更改的是那种被获取的对象,
     * 例如sysUser获取Role,它们是多对多,我把Role看成相对多的一方,然后就需要更改Role里
     * 获取sysUser集合的get方法,因为sysUser获取角色集合后,角色再获取的用户的话,就会一直
     * 循环下去,知道堆栈溢出
     */
    public SysUser findSysUser() {
        return sysUser;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setSysUser(SysUser sysUser) {
        this.sysUser = sysUser;
    }

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        this.department = department;
    }

    public String getPosition() {
        return position;
    }

    public void setPosition(String position) {
        this.position = position;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

}
