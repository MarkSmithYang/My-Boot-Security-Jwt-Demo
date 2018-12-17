package com.yb.boot.security.jwt.exception;

import com.yb.boot.security.jwt.common.ResultInfo;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(AccessDeniedException.class)
    public ResultInfo accessDeniedExceptionHandler(AccessDeniedException e) {
        log.error(e.getMessage(), e);
        return ResultInfo.status(HttpStatus.FORBIDDEN.value())
                .message("权限不足");
    }

    /**
     * 处理参数校验异常
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResultInfo missingServletRequestParameterExceptionHandler(MissingServletRequestParameterException e) {
        log.error(e.getMessage(), e);
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(e.getMessage());
    }

    /**
     * json对象提交参数的校验异常捕获处理(需要有@RequestBody注解来解析json对象,可由此分辨)
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResultInfo methodArgumentNotValidExceptionHandler(MethodArgumentNotValidException e) {
        BindingResult bindingResult = e.getBindingResult();
        String errorMesssage = " ";
        for (FieldError fieldError : bindingResult.getFieldErrors()) {
            errorMesssage += fieldError.getDefaultMessage() + " ";
        }
        log.info(e.getMessage());
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(errorMesssage);
    }

    /**
     * 接口单个参数的校验异常捕捉
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ConstraintViolationException.class)
    public ResultInfo constraintViolationExceptionHandler(ConstraintViolationException e) {
        List<String> list = new ArrayList<>();
        Set<ConstraintViolation<?>> set = e.getConstraintViolations();
        set.forEach(s -> list.add(s.getMessage()));
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(CollectionUtils.isNotEmpty(list) ? list.toString() : null);
    }

    /**
     * 运行时异常捕获处理---表单方式提交参数校验参数非空等捕获异常信息处理
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(RuntimeException.class)
    public ResultInfo runtimeExceptionHandler(RuntimeException e) {
        log.info("运行时异常:" + e.getMessage());
        //处理因为表单提交而不是json对象提交参数校验失败的情况
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message("网络异常");
    }

    /**
     * Exception异常捕获处理--表单方式提交参数校验参数非空等捕获异常信息处理
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(Exception.class)
    public ResultInfo exceptionHandler(Exception e) {
        log.info("Exception异常:" + e.getMessage());
        if (StringUtils.isBlank(e.getMessage())) {
            return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                    .message("网络异常");
        }
        return ResultInfo.status(HttpStatus.BAD_REQUEST.value())
                .message(getErrorMessage(e.getMessage()));
    }

    /**
     * 表单方式提交参数校验参数非空等捕获异常信息处理
     */
    private String getErrorMessage(String message) {
        String error = "";
        if (StringUtils.isNotBlank(message)) {
            String[] array = message.split(" ");
            if (ArrayUtils.isNotEmpty(array)) {
                for (int i = 0; i < array.length; i++) {
                    if (array[i].matches(".*[\u4e00-\u9fa5]{1,}.*")) {
                        error = error + array[i];
                    }
                }
            }
        }
        return error;
    }

    //通过Exception或者RuntimeException来返回统一的中文网络异常或者什么的,通过日志log打印具体的e.getMessage
    //-------------------事实上,如果没有处理成中文提示,那就没什么意义,而且影响体验-----------------------

}
