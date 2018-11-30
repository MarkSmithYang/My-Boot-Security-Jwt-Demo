package com.yb.springsecurity.jwt.common;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
  * Description: jwt的信息封装类
  * author yangbiao
  * date 2018/11/21
 */
@ApiModel("jwt的信息封装类")
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    @ApiModelProperty("授权者")
    private String iss;

    @ApiModelProperty("观众,受众")
    private String aud;

    @ApiModelProperty("经过base64编码的秘钥")
    private String secret;

    @ApiModelProperty("token的过期时间")
    private int expireSeconds;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public int getExpireSeconds() {
        return expireSeconds;
    }

    public void setExpireSeconds(int expireSeconds) {
        this.expireSeconds = expireSeconds;
    }
}
