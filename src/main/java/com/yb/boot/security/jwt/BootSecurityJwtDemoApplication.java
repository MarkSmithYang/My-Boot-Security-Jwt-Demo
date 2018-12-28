package com.yb.boot.security.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;

@EnableWebMvc
@SpringBootApplication
@EnableTransactionManagement//开启事物支持
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

    /**
     * 在启动过程中执行有@PostConstruct注解的方法
     */
    @PostConstruct
    public void startLoader(){
        System.err.println("这个和ApplicationRunnerImpl类的功能差不多,这个方法是在容器加载过程中执行," +
                "而ApplicationRunnerImpl则是在容器加载完成以后,就是打印出端口后才会执行");
        System.err.println(LocalDateTime.now());
    }


}





