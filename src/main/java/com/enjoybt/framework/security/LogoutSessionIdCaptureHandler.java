package com.enjoybt.framework.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * LogoutHandler
 * - invalidate-session="true" 로 세션이 무효화되기 전에 세션 ID를 캡처하여 request attribute에 저장
 * - CustomLogoutSuccessHandler에서 request.getAttribute("LOGOUT_SESSION_ID")로 사용
 */
public class LogoutSessionIdCaptureHandler implements LogoutHandler {

    public static final String ATTR_NAME = "LOGOUT_SESSION_ID";

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            request.setAttribute(ATTR_NAME, session.getId());
        }
    }
}
