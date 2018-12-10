package com.yb.boot.security.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableTransactionManagement//开启事物支持
//@EnableWebMvc//启动mvc的web配置--据说可以解决静态资源加载不了的问题
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启方法注解权限控制
public class BootSecurityJwtDemoApplication{

    public static void main(String[] args) {
        SpringApplication.run(BootSecurityJwtDemoApplication.class, args);
    }

    //--------------------------------------------------------------------
    //与其做一个工具,还不如自己实例化然后自动注入使用
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
    //--------------------------------------------------------------------
}





