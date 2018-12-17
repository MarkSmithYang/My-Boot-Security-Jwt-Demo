package com.yb.boot.security.jwt.request;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import javax.validation.constraints.NotBlank;
import java.io.Serializable;

/**
  * Description: 刷新token传递的token封装
  * author yangbiao
  * date 2018/12/4
 */
@ApiModel("刷新token参数封装类")
public class RefreshToken implements Serializable {
    private static final long serialVersionUID = 436863891776697851L;

    @NotBlank(message = "访问用token不能为空")
    @ApiModelProperty("访问用token")
    public String accessToken;

    @NotBlank(message = "刷新用token不能为空")
    @ApiModelProperty("刷新用token")
    public String refreshToken;

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
}
