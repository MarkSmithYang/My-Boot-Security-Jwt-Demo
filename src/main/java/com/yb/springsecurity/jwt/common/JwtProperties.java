package com.yb.springsecurity.jwt.common;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

/**
  * Description: jwt的信息封装类
  * author yangbiao
  * date 2018/11/21
 */
@ApiModel("jwt的信息封装类")
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    @ApiModelProperty("jwt发布者")
    private String iss;

    @ApiModelProperty("jwt接收方")
    private String aud;

    @ApiModelProperty("签名秘钥")
    private String secret;

    @ApiModelProperty("过期时间-毫秒")
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
