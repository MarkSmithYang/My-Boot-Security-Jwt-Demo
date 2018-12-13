package com.yb.boot.security.jwt.request;

import com.yb.boot.security.jwt.common.CommonDic;
import com.yb.boot.security.jwt.exception.ParameterErrorException;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

/**
 * Description:用户注册(添加)信息封装类
 * author yangbiao
 * date 2018/12/12
 */
@ApiModel("用户注册(添加)信息封装类")
public class UserRegister {

    @Length(max = 20, message = "用户名不能大于20字")
    @NotBlank(message = "用户名不能为空")
    @ApiModelProperty("用户名")
    private String username;

    @Length(min = 3, max = 16, message = "密码只允许6到16个字符")
    @NotBlank(message = "密码不能为空")
    @ApiModelProperty("密码")
    private String password;

    @Length(min = 3, max = 16, message = "确认密码只允许6到16个字符")
    @NotBlank(message = "确认密码不能为空")
    @ApiModelProperty("确认密码")
    private String rePassword;

    @Length(max = 25, message = "用户部门不能大于25字")
    @ApiModelProperty("用户部门")
    private String department;

    @Length(max = 25, message = "用户职位不能大于25字")
    @ApiModelProperty("用户职位")
    private String position;

    @NotBlank(message = "电话不能为空")
    @Pattern(regexp = "^(13[0-9]|14[579]|15[0-3,5-9]|16[6]|17[0135678]|18[0-9]|19[89])\\d{8}$", message = "电话有误")
    @ApiModelProperty("用户电话")
    private String phone;

    @Length(max = 10, message = "用户类型长度过长")
    @NotBlank(message = "用户类型不能为空")
    @ApiModelProperty("用户类型(前台或后台等)")
    private String from;

    /**
     * 校验密码和确认密码是否一致
     */
    public boolean checkPasswordEquals() {
        return StringUtils.isNotBlank(this.password) ? this.password.equals(this.rePassword) : false;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (StringUtils.isNotBlank(username)) {
            username = username.trim();
        }
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        if (StringUtils.isNotBlank(password)) {
            password = password.trim();
        }
        this.password = password.trim();

    }

    public String getRePassword() {
        return rePassword;
    }

    public void setRePassword(String rePassword) {
        if (StringUtils.isNotBlank(rePassword)) {
            rePassword = rePassword.trim();
        }
        this.rePassword = rePassword;
    }

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        if (StringUtils.isNotBlank(department)) {
            department = department.trim();
        }
        this.department = department;
    }

    public String getPosition() {
        return position;
    }

    public void setPosition(String position) {
        if (StringUtils.isNotBlank(position)) {
            position = position.trim();
        }
        this.position = position;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        if (StringUtils.isNotBlank(phone)) {
            phone = phone.trim();
        }
        this.phone = phone;
    }

    public String getFrom() {
        if ("1".equals(this.from)) {
            return CommonDic.FROM_FRONT;
        } else if ("2".equals(this.from)) {
            return CommonDic.FROM_BACK;
        } else {
            ParameterErrorException.message("未知的用户类型");
        }
        return null;
    }

    public void setFrom(String from) {
        if (StringUtils.isNotBlank(from)) {
            from = from.trim();
        }
        this.from = from;
    }
}
