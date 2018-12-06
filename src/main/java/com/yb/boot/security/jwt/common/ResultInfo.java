package com.yb.boot.security.jwt.common;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * @author yangbiao
 * @Description:返回数据的封装类
 * @date 2018/11/2
 */
@ApiModel("Restful风格数据封装类")
public class ResultInfo<T> {
    private static final String MESSAGE_SUCCESS = "success";
    private static final Integer STATUS_SUCCESS = 200;
    private static final Integer STATUS_BADREQUEST = 400;

    @ApiModelProperty("返回信息")
    private String message;
    @ApiModelProperty("返回状态码")
    private Integer status;
    @ApiModelProperty("返回数据")
    private T data;

    //--------------------------------用于链式编程返回异常捕获信息-----------------------------------

    public static ResultInfo status(Integer status) {
        ResultInfo info = new ResultInfo<>();
        info.setStatus(status);
        return info;
    }

    /**
     * 由于直接通过类名调用上面的status静态方法返回的是对象,所以下面的这个方法就不能是静态的了,
     * 而且只能先调用status方法,然后再调用message方法这样的链式编程
     */
    public ResultInfo message(String message) {
        //不能再次new对象,不然前面的status会被丢失的,使用它自己赋值后返回自己即可
        this.setMessage(message);
        return this;
    }

    //--------------------------------用于链式编程返回异常捕获信息-----------------------------------
    public static <T> ResultInfo<T> success(T t) {
        ResultInfo<T> info = new ResultInfo<>();
        info.setStatus(STATUS_SUCCESS);
        info.setMessage(MESSAGE_SUCCESS);
        info.setData(t);
        return info;
    }


    /**
     * 这个方法基本不会用的,我通常是抛出异常,在controller层统一处理异常的类里再统一定义
     *
     * @param errorMessage
     * @param <T>
     * @return
     */
    public static <T> ResultInfo<T> error(String errorMessage) {
        ResultInfo<T> info = new ResultInfo<>();
        info.setStatus(STATUS_BADREQUEST);
        info.setMessage(errorMessage);
        return info;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
