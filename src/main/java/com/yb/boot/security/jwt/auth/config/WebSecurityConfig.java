package com.yb.boot.security.jwt.auth.config;

import com.yb.boot.security.jwt.auth.impl.AccessDeniedHandlerImpl;
import com.yb.boot.security.jwt.auth.other.CustomAuthenticationProvider;
import com.yb.boot.security.jwt.auth.other.JwtAuthenticationFilter;
import com.yb.boot.security.jwt.auth.other.RedisSecurityContextRepository;
import com.yb.boot.security.jwt.auth.impl.AuthenticationEntryPointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * author yangbiao
 * Description:web的安全配置类
 * date 2018/11/30
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPoint;
    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;
    @Autowired
    private RedisSecurityContextRepository redisSecurityContextRepository;
    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandlerImpl;

    @Value("${allow.common.url}")
    private String[] commonUrl;
    @Value("${allow.server.url}")
    private String[] serverUrl;

    /**
     * 设置 HTTP 验证规则,用户模板最好在controller类上添加一层访问的路径,例如/auth/**
     * 这样在放开登录注册等接口的时候,就不容易造成放开一些不必要的接口服务
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //解决SpringBoot不允许加载iframe问题
        http.headers().frameOptions().disable();
        //关闭默认的登录认证
        http.httpBasic().disable()
                //添加处理ajxa的类实例
                .exceptionHandling().accessDeniedHandler(accessDeniedHandlerImpl)
                //添加拦截未登录用户访问的提示类实例,因为AuthenticationEntryPoint接口只有一个方法,可以用lambda来直接实现,而不用写类注入
                .authenticationEntryPoint(authenticationEntryPoint).and()
                //添加改session为redis存储实例
                .securityContext().securityContextRepository(redisSecurityContextRepository).and()
                //把session的代理创建关闭
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);

        // 关闭csrf验证,我们用jwt的token就不需要了
        http.csrf().disable()
                //对请求进行认证
                .authorizeRequests()
                //所有带/的请求都放行-->可以统一放到配置文件,然后读取过来,那样更方便修改特别是使用云配置的那种更方便
                //放开登录和验证码相关的接口(建议不要加层路径例如/auth,
                //会导致/security下的其他的不想放开的接口被放开等问题,直接放确定的最好,方正也没有几个接口)
                .antMatchers(serverUrl).permitAll()
                //.antMatchers(HttpMethod.GET, commonUrl).permitAll()//这个下面已经设置的了
                //访问指定路径的ip地址校验,访问指定路径的权限校验--这些接口需要的权限可以通过注解@PreAuthorize等来设置
                //.antMatchers("/auth/yes").hasIpAddress("192.168.11.130")//这个注解目前还没发现,可以在这里设置
                //所有请求需要身份认证
                .anyRequest().authenticated().and()
                //添加一个过滤器,对其他请求的token进行合法性认证
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    //解决过滤器无法注入(依赖)Bean的问题
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    /**
     * 使用自定义身份验证组件
     * Spring Security中进行身份验证的是AuthenticationManager接口，ProviderManager是它的一个默认实现，
     * 但它并不用来处理身份认证，而是委托给配置好的AuthenticationProvider，每个AuthenticationProvider
     * 会轮流检查身份认证。检查后或者返回Authentication对象或者抛出异常。
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //使用自定义身份验证(组件)
        auth.authenticationProvider(customAuthenticationProvider);
    }

    @Override
    public void configure(WebSecurity web){
        // 设置不拦截规则,这里确实会优先上面的生效,其实如果这里设置了,上面就不用设置了
        web.ignoring().antMatchers(HttpMethod.GET,commonUrl);
    }

}
