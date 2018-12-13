package com.yb.boot.security.jwt.controller;

import com.yb.boot.security.jwt.auth.tools.AntiViolenceCheckTools;
import com.yb.boot.security.jwt.auth.tools.JwtTokenTools;
import com.yb.boot.security.jwt.common.CaptchaParam;
import com.yb.boot.security.jwt.common.CommonDic;
import com.yb.boot.security.jwt.common.JwtProperties;
import com.yb.boot.security.jwt.common.ResultInfo;
import com.yb.boot.security.jwt.request.RefreshToken;
import com.yb.boot.security.jwt.request.UserRegister;
import com.yb.boot.security.jwt.request.UserRequest;
import com.yb.boot.security.jwt.response.JwtToken;
import com.yb.boot.security.jwt.response.UserDetailsInfo;
import com.yb.boot.security.jwt.service.SecurityJwtService;
import com.yb.boot.security.jwt.utils.LoginUserUtils;
import com.yb.boot.security.jwt.utils.RealIpGetUtils;
import com.yb.boot.security.jwt.utils.VerifyCodeUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import redis.clients.util.IOUtils;
import sun.nio.ch.IOUtil;

import javax.annotation.security.PermitAll;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.text.View;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * author yangbiao
 * Description:控制层代码
 * date 2018/11/30
 */
@Api("我的controller测试")
@Controller
@Validated
@CrossOrigin//处理跨域
//@RequestMapping("/auth")//添加一层路径是必要的,
//我现在只在需要放开的接口添加一层共同的路径,便于放开路径/auth/login和/auth/verifyCode,
//这种只放开部分接口,在类上加一层路径没什么用处,你还得逐个放开,所以对于需要放开的加就可以了
//这种方式还有一个弊端,就是因为放开的是/auth/**,所以随便一个路径只要在/security下就可以直接跳过
//拦截,从而报error错误,信息会到error页面去,而不是提示用户去登录,故而感觉还是直接放开指定接口即可,
//反正接口也不多,而且不容易因为漏掉/security而出现的各种问题.
public class SecurityJwtController {
    public static final Logger log = LoggerFactory.getLogger(SecurityJwtController.class);

    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private SecurityJwtService securityJwtService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private RedisTemplate<String, Serializable> redisTemplate;

    private final String CODE_HEADER = "ae81cac2";

    @GetMapping("/toLogin")
    public String toLogin() {
        return "/login";
    }

    @GetMapping("/loginBack")
    public String loginBack() {
        return "/loginBack";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/index")
    public String index() {
        return "/index";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/queryUserList")
    public String queryUserList() {
        return "/index";
    }

//    @PreAuthorize("isAuthenticated()")
    @PostMapping("/addUser")
    public String addUser(@Valid UserRegister userRegister) {
        securityJwtService.addUser(userRegister);
        return "success";
    }

    @PreAuthorize("isAuthenticated()")
    //如果想要走自己写的登出接口,接口不能为/logout,这个默认会走配置那里的.logout()
    @GetMapping("/customLogout")
    public String customLogout(HttpServletResponse response, HttpServletRequest request) {
        //清空用户的登录
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        //正确的登录姿势
        if (auth != null) {
            //调用api登出
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "forward:/toLogin";
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    @PreAuthorize("hasAuthority('query')")
    @ApiOperation(value = "yes的查询", notes = "query权限可访问")
    @GetMapping("/yes")
    @ResponseBody
    public ResultInfo<List<String>> yes() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("yes");
            add(LoginUserUtils.getUsername());
            System.err.println(LoginUserUtils.getUserDetails());
        }});
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    //hasPermission需要自定义来实现,反正SimpleGrantedAuthority构造名称就叫role
    //所以可以把权限当成角色来看就行了,只是有些角色含有很多小角色而已,为了好看
    //一点可以使用hasAuthority代替hasRole,但是效果都一样,而且自动补全会把所有的
    //权限角色模块都显示出来供你选择
    @PreAuthorize("hasAuthority('update')")
    @ApiOperation(value = "hello的查询", notes = "需要update权限可访问")
    @GetMapping("/hello")
    @ResponseBody
    public ResultInfo<List<String>> hello() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("hello");
        }});
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    @PreAuthorize("hasAuthority('" + CommonDic.ROLE_ + "admin')")//hasAuthority和hasRole功能一样
    @ApiOperation(value = "world的查询", notes = "admin角色可访问")
    @GetMapping("/world")
    @ResponseBody
    public ResultInfo<List<String>> world() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("world");
        }});
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    @PreAuthorize("hasAuthority('" + CommonDic.MODULE_ + "center')")//方法执行之前执行认证
    @ApiOperation(value = "users的查询", notes = "要center模块权限")
    @GetMapping("/users")
    @ResponseBody
    public ResultInfo<List<String>> users() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("rose");
            add("jack");
            add("mark");
        }});
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    //@PreAuthorize("principal.username.equals(#username)")//通过principal的写法就是解析不了表达式
    //@PreAuthorize("principal.username.toString().equals(#username)")//字符串化也不得行
    @PreAuthorize("authentication.name.equals(#username)")
    //这个直接在安全上下文取的就可以,或许是因为解析token的时候,只设置了SecurityContent而没有UserDetails
    @ApiOperation(value = "list的查询", notes = "输入登录用户名可访问")
    @GetMapping("/list")
    @ResponseBody
    public ResultInfo<List<String>> list(@RequestParam @Length(min = 10, message = "长度过长") String username) {
        return ResultInfo.success(new ArrayList<String>() {{
            add("rose1");
            add("jack2");
            add("mark3");
        }});
    }

    //@PreFilter和@PostFilter用来对集合类型的参数或者返回值进行过滤
    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    @ApiOperation(value = "getMessage的查询", notes = "无权可访问")
    @GetMapping("/getMessage")
    @ResponseBody
    public ResultInfo<String> getMessage() {
        return ResultInfo.success("我不需要权限就可以访问哦,在接口方法上放开,而不是通过antMatch");
    }

    @PreAuthorize("isAuthenticated()")
    @ApiOperation("刷新token")
    @PostMapping("/refreshToken")
    @ResponseBody
    public ResultInfo<JwtToken> refreshToken(@Valid @RequestBody RefreshToken refreshToken, HttpServletResponse response) {
        //判断token的合法性并解析出用户详细信息
        UserDetailsInfo detailsInfo = JwtTokenTools.getUserByJwt(refreshToken.getAccessToken(), jwtProperties);
        //生成token信息
        String accessToken = JwtTokenTools.createAccessToken(detailsInfo, jwtProperties.getExpireSeconds(), response, jwtProperties);
        //封装token返回
        if (StringUtils.isNotBlank(accessToken)) {
            JwtToken jwtToken = new JwtToken();
            jwtToken.setAccessToken(CommonDic.TOKEN_PREFIX + accessToken);
            jwtToken.setRefreshToken(CommonDic.TOKEN_PREFIX + refreshToken.getRefreshToken());
            jwtToken.setTokenExpire(jwtProperties.getExpireSeconds());
            //返回数据
            return ResultInfo.success(jwtToken);
        }
        return ResultInfo.error("刷新token失败");

    }

    //如果是表单的提交就不用@RequestBody,swagger用起来也比较舒服,如果前端传回来的是json对象,那么就要用
    //就算是直接访问这个接口,跳过验证码的验证,这里也做了登录失败5次就等待时间
//    @ApiOperation("前台登录")
//    @PostMapping("/frontLogin")
//    @ResponseBody
//    public ResultInfo<JwtToken> frontLogin(@Valid UserRequest userRequest, HttpServletRequest request,
//                                           HttpServletResponse response) {
//        //获取用户名
//        return getJwtTokenResultInfo(userRequest, request, response,CommonDic.FROM_FRONT);
//    }

    @ApiOperation("前台登录")
    @PostMapping("/frontLogin")
    public String frontLogin(@Valid UserRequest userRequest, HttpServletRequest request,
                             HttpServletResponse response) {
        getJwtTokenResultInfo(userRequest, request, response, CommonDic.FROM_FRONT);
        //登录成功之后跳转
        return "/index";
    }

    //如果是表单的提交就不用@RequestBody,swagger用起来也比较舒服,如果前端传回来的是json对象,那么就要用
    //就算是直接访问这个接口,跳过验证码的验证,这里也做了登录失败5次就等待时间
    //@PermitAll//实测此注解不能放开接口,必须登录
//    @ApiOperation("后台登录")
//    @PostMapping("/backLogin")
//    @ResponseBody
//    public ResultInfo<JwtToken> backLogin(@Valid @RequestBody UserRequest userRequest, HttpServletRequest request,
//                                          HttpServletResponse response) {
//        return getJwtTokenResultInfo(userRequest, request, response, CommonDic.FROM_BACK);
//    }

    @ApiOperation("后台登录")
    @PostMapping("/backLogin")
    public String backLogin(@Valid UserRequest userRequest, HttpServletRequest request,
                            HttpServletResponse response) throws ServletException, IOException {
        getJwtTokenResultInfo(userRequest, request, response, CommonDic.FROM_BACK);
        //登录成功之后跳转
        return "/layout";
    }

    /**
     * 登录公共部门代码抽取
     */
    private ResultInfo<JwtToken> getJwtTokenResultInfo(UserRequest userRequest, HttpServletRequest request,
                                                       HttpServletResponse response, String from) {
        //获取用户名
        String username = userRequest.getUsername();
        //获取用户真实地址
        String ipAddress = RealIpGetUtils.getIpAddress(request);
        //拼接存储key用以存储信息到redis
        String key = CommonDic.LOGIN_SIGN_PRE + ipAddress + username;
        //检测用户登录次数是否超过指定次数,超过就不再往下验证用户信息
        AntiViolenceCheckTools.checkLoginTimes(redisTemplate, key);
        //检测用户名登录失败次数--->根据自己的需求添加我这里就用一个,其他的注释
        //AntiViolenceCheckTools.usernameOneDayForbidden(redisTemplate, username);
        //检测登录用户再次ip的登录失败的次数
        //AntiViolenceCheckTools.ipForbidden(request,redisTemplate);
        //进行用户登录认证
        JwtToken jwtToken = securityJwtService.authUser(userRequest, from, response, request);
        //成功登录后清除用户登录失败(允许次数类)的次数
        AntiViolenceCheckTools.checkLoginTimesClear(redisTemplate, key);
        //成功登录后清零此用户名登录失败的次数
        //AntiViolenceCheckTools.usernameOneDayClear(redisTemplate, username);
        //成功登录后清零此ip登录失败的次数
        //AntiViolenceCheckTools.ipForbiddenClear(request, redisTemplate);
        //返回数据
        return ResultInfo.success(jwtToken);
    }

    //----------------------验证码都是提供生成接口和校验接口有前端请求生成和校验------------------------------

    @GetMapping("/verifyCodeCheck")
    @ResponseBody
    public String verifyCodeCheck(String verifyCode, HttpServletRequest request) {
        if (StringUtils.isNotBlank(verifyCode)) {
            //获取服务ip
            String ipAddress = RealIpGetUtils.getIpAddress(request);
            String key = CommonDic.VERIFYCODE_SIGN_PRE + ipAddress;
            //获取redis上的存储的(最新的)验证码
            String code = (String) redisTemplate.opsForValue().get(key);
            //校验验证码
            if (StringUtils.isNotBlank(code) && code.contains("@&")) {
                code = code.split("@&")[1];
                if (verifyCode.toLowerCase().equals(code.toLowerCase())) {
                    return "true";
                }
            } else {
                return "expir";
            }
        }
        return "false";
    }

    @GetMapping("/verifyCode")
    public void verifyCode(HttpServletResponse response, HttpServletRequest request) {
        Integer times;
        //获取服务ip
        String ipAddress = RealIpGetUtils.getIpAddress(request);
        //拼接存储redis的key
        String key = CommonDic.VERIFYCODE_SIGN_PRE + ipAddress;
        //获取验证码及其刷新次数信息
        String code = (String) redisTemplate.opsForValue().get(key);
        if (StringUtils.isNotBlank(code) && code.contains("@&")) {
            times = Integer.valueOf(code.split("@&")[0]);
            //判断刷新次数
            if (times > CommonDic.REQUEST_MAX_TIMES) {
                //结束程序--等待redis上的数据过期再重新再来
                return;
            }
            //增加次数
            times++;
        } else {
            times = 0;
        }
        //获取字符验证码
        String verifyCode = VerifyCodeUtils.generateVerifyCode(CommonDic.VERIFYCODE_AMOUNT);
        try {
            VerifyCodeUtils.outputImage(80, 30, response.getOutputStream(), verifyCode);
            //存储验证码并设置过期时间为5分钟--限制点击的次数,防止恶意点击
            redisTemplate.opsForValue().set(key, times + "@&" + verifyCode, CommonDic.VERIFYCODE_EXPIRED, TimeUnit.SECONDS);
        } catch (IOException e) {
            log.info("验证码输出异常");
            e.printStackTrace();
        }
    }

    //-------------------------------------另一种方式的验证码实现-------------------------------------------

    @ApiOperation(value = "获取图片验证码")
    @GetMapping("captcha")
    @ResponseBody
    public ResultInfo<CaptchaParam> captcha(@ApiParam("宽度") @RequestParam(defaultValue = "110") int width, @ApiParam("高度") @RequestParam(defaultValue = "34") int height) throws IOException {
        String code = VerifyCodeUtils.generateVerifyCode(4);
        String base64img = VerifyCodeUtils.base64Image(width, height, code);
        String signature = bCryptPasswordEncoder.encode(CODE_HEADER + code.toUpperCase());
        CaptchaParam data = new CaptchaParam(base64img, signature);
        return ResultInfo.success(data);
    }

    @ApiOperation(value = "校验验证码")
    @PostMapping("checkCaptcha")
    @ResponseBody
    public ResultInfo<String> checkCaptcha(@Valid @RequestBody CaptchaParam param) {
        if (bCryptPasswordEncoder.matches(CODE_HEADER + param.getCaptcha().toUpperCase(), param.getSignature())) {
            return ResultInfo.success("验证码正确");
        }
        return ResultInfo.error("验证码错误");
    }
}
