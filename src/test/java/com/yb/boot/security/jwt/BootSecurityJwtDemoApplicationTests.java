package com.yb.boot.security.jwt;

import com.yb.boot.security.jwt.request.UserRegister;
import com.yb.boot.security.jwt.service.SecurityJwtService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

@RunWith(SpringRunner.class)
@SpringBootTest
public class BootSecurityJwtDemoApplicationTests {

    @Autowired
    private SecurityJwtService securityJwtService;

    @Test
    public void contextLoads() {
        UserRegister userRegister = new UserRegister();
        userRegister.setDepartment("1");
        userRegister.setFrom("1");
        userRegister.setPassword("111");
        userRegister.setRePassword("111");
        userRegister.setPhone("1");
        userRegister.setPosition("1j");
        userRegister.setUsername("1Jj");
        securityJwtService.addUser(userRegister);
        System.err.println("------------------------------ok");

    }
}
