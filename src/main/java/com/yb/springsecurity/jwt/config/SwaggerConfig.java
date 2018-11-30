package com.yb.springsecurity.jwt.config;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.*;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * author yangbiao
 * Description:swagger配置类--实测并不需要放在和主应用类统计目录也可以
 * date 2018/11/30
 */
@Profile({"dev", "test"})
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    /**
     * 不需要登录就能访问的接口url,这个就会在swagger-ui.hmt显示的时候没有那个锁的图标,
     * 也就是不需要token就可以访问
     */
    @Value("${allow.server.url}")
    private String[] securityPermit;

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("SpringSecurity")
                .description("用户user服务")
                .contact(new Contact("jack", "https://swagger.io/", "jack@163.com"))
                .version("1.0").build();
    }

    @Bean
    public Docket createRestApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .securitySchemes(new ArrayList<ApiKey>() {{
                    add(new ApiKey("TOKEN用户认证", "Authorization", "header"));
                }})
                .securityContexts(new ArrayList<SecurityContext>() {{
                    add(securityContext());
                }})
                .apiInfo(apiInfo())
                .select()
                //通过指定包路径扫描(准确,但是不易修改和通用)
                .apis(RequestHandlerSelectors.basePackage("com.yb.springsecurity.jwt.controller"))
                //通过注解名称去扫描(几乎不需要更改什么)
                //.apis(RequestHandlerSelectors.withClassAnnotation(Controller.class))
                .paths(PathSelectors.any())
                .build()
                .directModelSubstitute(LocalDateTime.class, String.class)
                .directModelSubstitute(Timestamp.class, Long.class);
    }


    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(defaultAuth())
                .forPaths(path -> !StringUtils.equalsAny(path, securityPermit))
                .build();
    }

    private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[]{authorizationScope};
        return new ArrayList<SecurityReference>() {{
            // reference 要和 ApiKey 名字一致
            add(new SecurityReference("TOKEN用户认证", authorizationScopes));
        }};
    }

    @Bean
    SecurityConfiguration security() {
        return SecurityConfigurationBuilder.builder()
                .clientId("test-app-client-id")
                .clientSecret("test-app-client-secret")
                .realm("test-app-realm")
                .appName("test-app")
                .scopeSeparator(",")
                .additionalQueryStringParams(null)
                .useBasicAuthenticationWithAccessCodeGrant(false)
                .build();
    }

    @Bean
    public UiConfiguration uiConfig() {
        return UiConfigurationBuilder.builder()
                .deepLinking(true)
                .displayOperationId(false)
                // 底部 models 默认展开深度 0不展开, 默认展开太长了
                .defaultModelsExpandDepth(0)
                // 接口文档中实体的默认展开深度
                .defaultModelExpandDepth(1)
                .defaultModelRendering(ModelRendering.EXAMPLE)
                // 显示请求的响应时间
                .displayRequestDuration(true)
                .docExpansion(DocExpansion.NONE)
                // tag过滤
                .filter(false)
                .maxDisplayedTags(null)
                .operationsSorter(OperationsSorter.ALPHA)
                .showExtensions(false)
                .tagsSorter(TagsSorter.ALPHA)
                .validatorUrl(null)
                .build();
    }

}
