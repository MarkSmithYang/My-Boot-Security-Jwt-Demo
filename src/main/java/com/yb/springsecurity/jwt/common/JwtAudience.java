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
@ConfigurationProperties(prefix = "jwt.audience")
public class JwtAudience {

    @ApiModelProperty("授权者")
    private String iss;

    @ApiModelProperty("鉴权者")
    private String aud;

    @ApiModelProperty("经过base64编码的秘钥")
    private String base64Secret;

    @ApiModelProperty("token的过期时间")
    private int expirationSeconds;

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

    public String getBase64Secret() {
        return base64Secret;
    }

    public void setBase64Secret(String base64Secret) {
        this.base64Secret = base64Secret;
    }

    public int getExpirationSeconds() {
        return expirationSeconds;
    }

    public void setExpirationSeconds(int expirationSeconds) {
        this.expirationSeconds = expirationSeconds;
    }
}
