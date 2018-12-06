package com.yb.boot.security.jwt.exception;

/**
 * author yangbiao
 * Description:自定义的运行时的参数校验异常
 * date 2018/11/30
 */
public class RetryTimeException extends RuntimeException {

    /**
     * 重写父类构造,并把自己接收到的异常信息传递给父类覆盖其信息
     *
     * @param message
     */
    public RetryTimeException(String message) {
        super(message);
    }

    /**
     * 抛出自定义异常信息的方法
     * @param exceptionMessage
     */
    public static void message(String exceptionMessage) {
        throw new RetryTimeException(exceptionMessage);
    }
}
