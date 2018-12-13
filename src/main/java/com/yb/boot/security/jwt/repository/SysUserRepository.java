package com.yb.boot.security.jwt.repository;

import com.yb.boot.security.jwt.model.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author yangbiao
 * @Description:
 * @date 2018/11/30
 */
public interface SysUserRepository extends JpaRepository<SysUser,String> {

    SysUser findByUsername(String username);

    SysUser findByUsernameAndUserFrom(String username, String from);
}
