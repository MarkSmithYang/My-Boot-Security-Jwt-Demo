package com.yb.springsecurity.jwt.controller;

import com.yb.springsecurity.jwt.auth.tools.AntiViolenceCheckTools;
import com.yb.springsecurity.jwt.auth.tools.JwtTokenTools;
import com.yb.springsecurity.jwt.common.CaptchaParam;
import com.yb.springsecurity.jwt.common.CommonDic;
import com.yb.springsecurity.jwt.common.JwtProperties;
import com.yb.springsecurity.jwt.common.ResultInfo;
import com.yb.springsecurity.jwt.request.RefreshToken;
import com.yb.springsecurity.jwt.request.UserRequest;
import com.yb.springsecurity.jwt.response.JwtToken;
import com.yb.springsecurity.jwt.response.UserDetailsInfo;
import com.yb.springsecurity.jwt.service.SecurityJwtService;
import com.yb.springsecurity.jwt.utils.RealIpGetUtils;
import com.yb.springsecurity.jwt.utils.VerifyCodeUtils;
import io.jsonwebtoken.Claims;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.File;
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

    @GetMapping("/logout")
    public String logout() {
        //清空用户的登录
        SecurityContextHolder.getContext().setAuthentication(null);
        return "/login";
    }

    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    @PreAuthorize("hasAuthority('query')")
    @ApiOperation("yes的查询")
    @GetMapping("/yes")
    @ResponseBody
    public ResultInfo<List<String>> yes() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("yes");
        }});
    }

    @PreAuthorize("hasPermission('update')")
    @ApiOperation("hello的查询")
    @GetMapping("/hello")
    @ResponseBody
    public ResultInfo<List<String>> hello() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("hello");
        }});
    }

    @PreAuthorize("hasAuthority('"+CommonDic.ROLES_+"admin,manager')")//和hasRole功能一样
    @ApiOperation("world的查询")
    @GetMapping("/world")
    @ResponseBody
    public ResultInfo<List<String>> world() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("world");
        }});
    }

    //@Secured("admin,manager")//不支持Spring EL表达式
    //@PostAuthorize("hasAuthority('')")//方法调用之后执行认证
    @PreAuthorize("hasAuthority('"+CommonDic.MODULES_+"center')")//方法执行之前执行认证
    @ApiOperation("users的查询")
    @GetMapping("/users")
    @ResponseBody
    public ResultInfo<List<String>> users() {
        return ResultInfo.success(new ArrayList<String>() {{
            add("rose");
            add("jack");
            add("mark");
        }});
    }

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
            jwtToken.setRefreshToken(CommonDic.TOKEN_PREFIX + refreshToken);
            jwtToken.setTokenExpire(jwtProperties.getExpireSeconds());
            //返回数据
            return ResultInfo.success(jwtToken);
        }
        return ResultInfo.error("刷新token失败");

    }

    @ApiOperation("前台登录")
    @PostMapping("/frontLogin")
    @ResponseBody
    public ResultInfo<JwtToken> frontLogin(@Valid UserRequest userRequest, HttpServletRequest request,
                                           HttpServletResponse response) {
        //获取用户名
        String username = userRequest.getUsername();
        //获取用户真实地址
        String ipAddress = RealIpGetUtils.getIpAddress(request);
        //拼接存储key用以存储信息到redis
        String key = CommonDic.LOGIN_SIGN_PRE + ipAddress + username;
        //检测用户登录次数是否超过指定次数,超过就不再往下验证用户信息
        //AntiViolenceCheckTools.checkLoginTimes(redisTemplate, key);
        //检测用户名登录失败次数--->根据自己的需求添加我这里就用一个,其他的注释
        //AntiViolenceCheckTools.usernameOneDayForbidden(redisTemplate, username);
        //检测登录用户再次ip的登录失败的次数
        //AntiViolenceCheckTools.ipForbidden(request,redisTemplate);
        //进行用户登录认证
        JwtToken jwtToken = securityJwtService.authUser(userRequest, CommonDic.FROM_FRONT, response, request);
        //成功登录后清除用户登录失败(允许次数类)的次数
        AntiViolenceCheckTools.checkLoginTimesClear(redisTemplate, key);
        //成功登录后清零此用户名登录失败的次数
        //AntiViolenceCheckTools.usernameOneDayClear(redisTemplate, username);
        //成功登录后清零此ip登录失败的次数
        //AntiViolenceCheckTools.ipForbiddenClear(request, redisTemplate);
        //返回数据
        return ResultInfo.success(jwtToken);
    }

    //--------------------------------------------------------------------------------------------------------

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
}
