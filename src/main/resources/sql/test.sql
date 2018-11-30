/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50605
Source Host           : localhost:3306
Source Database       : securityjwt

Target Server Type    : MYSQL
Target Server Version : 50605
File Encoding         : 65001

Date: 2018-11-30 10:04:15
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for module
-- ----------------------------
DROP TABLE IF EXISTS `module`;
CREATE TABLE `module` (
`id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`module`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '模块英文名' ,
`module_cn`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '模块中文名' ,
PRIMARY KEY (`id`),
UNIQUE INDEX `UK_b6xqojmpvvjd685hq3p0itibn` (`module`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of module
-- ----------------------------
BEGIN;
INSERT INTO `module` VALUES ('1', '1', '1');
COMMIT;

-- ----------------------------
-- Table structure for module_users
-- ----------------------------
DROP TABLE IF EXISTS `module_users`;
CREATE TABLE `module_users` (
`modules_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`users_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
PRIMARY KEY (`modules_id`, `users_id`),
FOREIGN KEY (`modules_id`) REFERENCES `module` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
FOREIGN KEY (`users_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FKraqx5lrta03om9ecwfjej98ky` (`users_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of module_users
-- ----------------------------
BEGIN;
INSERT INTO `module_users` VALUES ('1', '1');
COMMIT;

-- ----------------------------
-- Table structure for permission
-- ----------------------------
DROP TABLE IF EXISTS `permission`;
CREATE TABLE `permission` (
`id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`permission`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '权限英文名' ,
`permission_cn`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '权限中文名' ,
PRIMARY KEY (`id`),
UNIQUE INDEX `UK_9kwkevw5na26e6qb4cbcbxaa4` (`permission`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of permission
-- ----------------------------
BEGIN;
INSERT INTO `permission` VALUES ('1', '1', '1');
COMMIT;

-- ----------------------------
-- Table structure for permission_modules
-- ----------------------------
DROP TABLE IF EXISTS `permission_modules`;
CREATE TABLE `permission_modules` (
`permissions_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`modules_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
PRIMARY KEY (`permissions_id`, `modules_id`),
FOREIGN KEY (`permissions_id`) REFERENCES `permission` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
FOREIGN KEY (`modules_id`) REFERENCES `module` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FK68s18la6flmsnh1hisogsyuea` (`modules_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of permission_modules
-- ----------------------------
BEGIN;
INSERT INTO `permission_modules` VALUES ('1', '1');
COMMIT;

-- ----------------------------
-- Table structure for permission_roles
-- ----------------------------
DROP TABLE IF EXISTS `permission_roles`;
CREATE TABLE `permission_roles` (
`permissions_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`roles_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
PRIMARY KEY (`permissions_id`, `roles_id`),
FOREIGN KEY (`permissions_id`) REFERENCES `permission` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
FOREIGN KEY (`roles_id`) REFERENCES `role` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FK9k4j9myvlxs8w8omv4awtpcpo` (`roles_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of permission_roles
-- ----------------------------
BEGIN;
INSERT INTO `permission_roles` VALUES ('1', '1');
COMMIT;

-- ----------------------------
-- Table structure for permission_users
-- ----------------------------
DROP TABLE IF EXISTS `permission_users`;
CREATE TABLE `permission_users` (
`permissions_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`users_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
PRIMARY KEY (`permissions_id`, `users_id`),
FOREIGN KEY (`permissions_id`) REFERENCES `permission` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
FOREIGN KEY (`users_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FKi2a37bu6ehvqx7oiqyvc58nou` (`users_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of permission_users
-- ----------------------------
BEGIN;
INSERT INTO `permission_users` VALUES ('1', '1');
COMMIT;

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
`id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`role`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '角色英文名' ,
`role_cn`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '角色中文名' ,
PRIMARY KEY (`id`),
UNIQUE INDEX `UK_bjxn5ii7v7ygwx39et0wawu0q` (`role`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of role
-- ----------------------------
BEGIN;
INSERT INTO `role` VALUES ('1', '1', '1');
COMMIT;

-- ----------------------------
-- Table structure for role_users
-- ----------------------------
DROP TABLE IF EXISTS `role_users`;
CREATE TABLE `role_users` (
`roles_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`users_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
PRIMARY KEY (`roles_id`, `users_id`),
FOREIGN KEY (`roles_id`) REFERENCES `role` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
FOREIGN KEY (`users_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FKlt1880i13pllwdmwejekuulqh` (`users_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of role_users
-- ----------------------------
BEGIN;
INSERT INTO `role_users` VALUES ('1', '1');
COMMIT;

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
`id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`create_time`  datetime NULL DEFAULT NULL COMMENT '创建时间' ,
`head_url`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '头像信息' ,
`password`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '密码' ,
`username`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '用户名' ,
`from`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '用户来源--前台/后台/app等' ,
PRIMARY KEY (`id`),
UNIQUE INDEX `UK_51bvuyvihefoh4kp5syh2jpi4` (`username`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
BEGIN;
INSERT INTO `sys_user` VALUES ('1', '2018-11-28 10:03:38', null, '$2a$10$taJbEr6KEj3HlhYxVAFEUOV01Y7ydH8SrJVqki4Pgj9qxV04vMSoK', 'jack', null);
COMMIT;

-- ----------------------------
-- Table structure for user_info
-- ----------------------------
DROP TABLE IF EXISTS `user_info`;
CREATE TABLE `user_info` (
`id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`department`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '部门' ,
`phone`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '电话' ,
`position`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '职位' ,
`sys_user_id`  varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL ,
PRIMARY KEY (`id`),
FOREIGN KEY (`sys_user_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
INDEX `FKohdq5x1mqvhojc0mkqafqcphn` (`sys_user_id`) USING BTREE 
)
ENGINE=InnoDB
DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci

;

-- ----------------------------
-- Records of user_info
-- ----------------------------
BEGIN;
INSERT INTO `user_info` VALUES ('1', '1', '1', '1', '1');
COMMIT;
