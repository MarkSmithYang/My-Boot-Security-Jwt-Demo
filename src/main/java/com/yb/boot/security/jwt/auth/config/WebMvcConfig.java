package com.yb.boot.security.jwt.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

/**
 * Description:springboot2.x支持的推荐WebMvcConfigurationSupport这个,有许多关于springMVC的配置
 * author yangbiao
 * date 2018/11/30
 */
@Configuration
public class WebMvcConfig extends WebMvcConfigurationSupport {

    /**
     * 视图控制器配置--没有登录用户都跳转到login.html页面的配置
     */
    @Override
    protected void addViewControllers(ViewControllerRegistry registry) {
        //接口/login跳转视图login(应该就是login.html或login.jsp,但是似乎没有什么效果)
        registry.addViewController("/toLogin").setViewName("/login");
        //处理/没有映射的问题(日志老是打印出来,也可以在controller写接口)--这里省了写/跳转到login的接口了
        registry.addViewController("/").setViewName("/login");
        super.addViewControllers(registry);
    }

    /**
     * 发现如果继承了WebMvcConfigurationSupport,
     * 则在yml中配置的相关内容会失效,需要重新指定静态资源,配置如下即可显示swagger-ui.html
     */
    @Override
    protected void addResourceHandlers(ResourceHandlerRegistry registry) {
        //显示swagger-ui.html必要的配置(实测),还要配合WebSecurityConfig放开swagger的资源才可以
        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
        //实测使用/**并不能放开静态资源,而使用了/static/**就可以了,因为路径是localhost:port/static/xxx/xx这样的形式的
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }

}
