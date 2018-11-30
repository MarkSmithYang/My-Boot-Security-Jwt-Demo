package com.yb.springsecurity.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableTransactionManagement//开启事物支持
@EnableWebMvc//启动mvc的web配置
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启方法注解权限控制
public class SpringsecurityJwtDemoApplication{

    public static void main(String[] args) {
        SpringApplication.run(SpringsecurityJwtDemoApplication.class, args);
    }

}










































