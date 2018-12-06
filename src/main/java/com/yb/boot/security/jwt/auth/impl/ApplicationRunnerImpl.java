package com.yb.boot.security.jwt.auth.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * @author yangbiao
 * @Description:CommandLineRunner,ApplicationRunner 接口是在容器启动成功后的最后一步回调(类似于开机自启动)
 * @date 2018/11/30
 */
@Component
public class ApplicationRunnerImpl implements ApplicationRunner {
    public static final Logger log = LoggerFactory.getLogger(ApplicationRunnerImpl.class);

    /**
     * 主要是通过容器启动它也跟着启动这个机制,完成我们想要加载的东西,这里方法参数没有什么用
     * 目前这里还实践怎么好用
     */
    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("这个ApplicationRunnerImpl类主要用来当服务启动完成后加载一些信息在服务内存," +
                "以供使用,或者处理一些需要这个时间段需要处理的业务等");
    }
}
