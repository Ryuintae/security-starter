package com.enjoybt.framework.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 *  Description : 사용자 세션/로그인 관련 페이지 컨트롤러
 */
@Controller
@RequestMapping(value="/security/")
public class SecurityController {
	
	/**
	 * Description : 로그인 페이지 
	 * @return (String)		- 페이지 URL
	 */
	@RequestMapping(value="login.do")
	public String viewLoginPage() {
		return "security/login";
	}

	@RequestMapping(value="signup.do")
	public String viewSignupPage() {
		return "security/signup";
	}

	// loginFail.do, logout.do 등 화면/리다이렉트 관련만 유지
}

