package com.yb.boot.security.jwt.request;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;

/**
 * author yangbiao
 * Description:封装用户登录信息的类
 * date 2018/11/30
 */
@ApiModel("用户信息封装类")
public class UserRequest {

    /**
     * 用户名
     */
    @Length(max = 20, message = "用户名不能大于20字")
    @NotBlank(message = "用户名不能为空")
    @ApiModelProperty("用户名")
    private String username;

    /**
     * 密码
     */
    @Length(min = 3, max = 16, message = "密码只允许6到16个字符")
    @NotBlank(message = "密码不能为空")
    @ApiModelProperty("密码")
    private String password;

    /**
     * 是否记住密码
     */
    @ApiModelProperty("是否记住密码")
    private boolean rememberMe = false;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (StringUtils.isNotBlank(username)) {
            this.username = username.trim();
        }
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        if (StringUtils.isNotBlank(password)) {
            this.password = password.trim();
        }
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
