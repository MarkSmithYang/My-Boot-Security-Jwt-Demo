package com.yb.springsecurity.jwt.response;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.Serializable;

/**
 * Description:登录成功返回的数据封装类
 * author yangbiao
 * date 2018/11/30
 */
@ApiModel("登录成功返回的数据封装类")
public class JwtToken implements Serializable {
    private static final long serialVersionUID = -5679643008444921620L;

    @ApiModelProperty("访问用token")
    public String accessToken;

    @ApiModelProperty("刷新用token")
    public String refreshToken;

    @ApiModelProperty("token类型")
    public String tokenType;

    @ApiModelProperty("token过期时间")
    public String tokenExpire;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getTokenExpire() {
        return tokenExpire;
    }

    public void setTokenExpire(String tokenExpire) {
        this.tokenExpire = tokenExpire;
    }
}
