package com.enjoybt.framework.security;

import com.enjoybt.framework.security.encoder.RSAGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;

/**
 *  Class Name : CustomUserNamePassword.java
 *  Description : 사용자 로그인시 패스워드를 관리하는 필터 
 *  Modification Information
 * 
 *     수정일			수정자				수정내용
 *   ---------------------------------------------------
 *   2018. 3. 15.	장재호				최초 생성
 *
 *  @author 장재호
 *  @since 2018. 3. 15.
 *  @version 1.0
 * 
 *  Copyright (C) 2018 by ㈜제이비티 All right reserved.
 */
public class CustomUserNamePassword extends UsernamePasswordAuthenticationFilter {
	
	/* 로그 관리 객체 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomUserNamePassword.class);
	
	/* (non-Javadoc)
	 * @see org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter#obtainPassword(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	protected String obtainPassword(HttpServletRequest request) {
		String realPass = "";
		String password = "";
		try {
				//TODO Security : 로그인 시 사용자 패스워드를 가져오는 부분(구간 암호화 시 변경 필요)
				password = request.getParameter(SPRING_SECURITY_FORM_PASSWORD_KEY);
				PrivateKey privateKey = RSAGenerator.getPrivateKey(request.getSession());
				realPass = RSAGenerator.getValue(privateKey, password);
		}catch(NullPointerException e) {
			LOGGER.error("CustomUserNamePassword Error", e);
		}
		
		if(realPass == null) {
			realPass = password;
		}
		return realPass;
	}
	
}
