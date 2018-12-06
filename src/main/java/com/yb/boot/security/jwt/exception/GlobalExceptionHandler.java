package com.yb.boot.security.jwt.exception;

import com.alibaba.fastjson.JSONException;
import com.yb.boot.security.jwt.common.ResultInfo;
import io.jsonwebtoken.ExpiredJwtException;
import org.hibernate.LazyInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.thymeleaf.exceptions.TemplateInputException;

import java.security.SignatureException;

/**
 * author yangbiao
 * Description:controller层的异常统一捕捉处理类
 * date 2018/11/30
 */
@RestControllerAdvice
@Profile(value = {"dev", "test"})//可以指定捕捉处理的环境
public class GlobalExceptionHandler {
    public static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ParameterErrorException.class)
    public ResultInfo parameterErrorExceptionHandler(ParameterErrorException e) {
        //这里的获取到的信息就是自定义的信息,因为父类的信息被覆盖了
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(LazyInitializationException.class)
    public ResultInfo lazyInitializationExceptionHandler(LazyInitializationException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(UnsupportedOperationException.class)
    public ResultInfo unsupportedOperationExceptionHandler(UnsupportedOperationException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(JSONException.class)
    public ResultInfo jsonExceptionHandler(JSONException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ArrayIndexOutOfBoundsException.class)
    public ResultInfo arrayIndexOutOfBoundsExceptionHandler(ArrayIndexOutOfBoundsException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InstantiationException.class)
    public ResultInfo instantiationExceptionHandler(InstantiationException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(TemplateInputException.class)
    public ResultInfo templateInputExceptionHandler(TemplateInputException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(NullPointerException.class)
    public ResultInfo nullPointerExceptionHandler(NullPointerException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResultInfo methodArgumentTypeMismatchExceptionHandler(HttpRequestMethodNotSupportedException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.METHOD_NOT_ALLOWED.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(RequestRejectedException.class)
    public ResultInfo requestRejectedExceptionExceptionHandler(RequestRejectedException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(RetryTimeException.class)
    public ResultInfo retryTimeExceptionHandler(RetryTimeException e) {
        log.info(e.getMessage());
        //这里的获取到的信息就是自定义的信息,因为父类的信息被覆盖了
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    /**
     * jwt验证秘钥(签名)异常
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(SignatureException.class)
    public ResultInfo signatureExceptionHandler(SignatureException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    /**
     * jwt的时间过期异常
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ExpiredJwtException.class)
    public ResultInfo expiredJwtExceptionHandler(ExpiredJwtException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResultInfo methodArgumentNotValidExceptionHandler(MethodArgumentNotValidException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler({MethodArgumentTypeMismatchException.class, HttpMessageNotReadableException.class})
    public ResultInfo methodArgumentTypeMismatchExceptionHandler(MethodArgumentTypeMismatchException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.OK.value())
                .message(e.getMessage());
    }

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResultInfo missingServletRequestParameterExceptionHandler(MissingServletRequestParameterException e) {
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.OK.value())
                .message(e.getMessage());
    }

//    @ResponseStatus(HttpStatus.FORBIDDEN)
//    @ExceptionHandler(AccessDeniedException.class)
//    public ResultInfo accessDeniedExceptionHandler(AccessDeniedException e) {
//        log.error(e.getMessage(), e);
//        return ResultInfo.status(HttpStatus.FORBIDDEN.value())
//                .message("权限不足");
//    }

    /**
     * 运行时异常捕获处理
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(RuntimeException.class)
    public ResultInfo runtimeExceptionHandler(RuntimeException e) {
        log.info("运行时异常:" + e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    /**
     * Exception异常捕获处理
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(Exception.class)
    public ResultInfo exceptionHandler(Exception e) {
        log.info("Exception异常:" + e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

}
