package com.yb.boot.security.jwt.utils;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

public class SendHeaders {

	/**
	 * @throws @Description:json对象的方式
	 * @return
	 */
	public static HttpHeaders getHeaders() {
		HttpHeaders headers = new HttpHeaders();
		MediaType type = MediaType.parseMediaType("application/json; charset=UTF-8");
		headers.setContentType(type);
		headers.add("Accept", MediaType.APPLICATION_JSON.toString());
		return headers;
	}

	/**
	 * @throws @Description:附件表单提交的方式(例如图片上传)
	 * @return
	 */
	public static HttpHeaders getHeader() {
		HttpHeaders headers = new HttpHeaders();
		MediaType type = MediaType.parseMediaType("multipart/form-data");
		headers.setContentType(type);
		headers.add("Accept", MediaType.APPLICATION_JSON.toString());
		return headers;
	}
}
