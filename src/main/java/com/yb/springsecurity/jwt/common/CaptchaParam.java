package com.yb.springsecurity.jwt.common;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.NotBlank;

/**
 * Description:获取验证码
 * author yangbiao
 * date 2018/12/4
 */
@ApiModel("获取验证码")
public class CaptchaParam {

    @NotBlank(message = "验证码不能为空")
    @ApiModelProperty(value = "验证码", notes = "获取验证码时返回Base64图片String, 校验时上传用户输入的code")
    private String captcha;

    @NotBlank(message = "签名不能为空")
    @ApiModelProperty("签名")
    private String signature;

    public CaptchaParam() {
    }

    public CaptchaParam(String captcha, String signature) {
        this.captcha = captcha;
        this.signature = signature;
    }

    public String getCaptcha() {
        return captcha;
    }

    public void setCaptcha(String captcha) {
        this.captcha = captcha;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
