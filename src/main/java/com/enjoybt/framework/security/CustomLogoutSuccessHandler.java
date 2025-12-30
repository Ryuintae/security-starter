package com.enjoybt.framework.security;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Autowired
    @Qualifier("subSqlSession")
    private SqlSessionTemplate sqlSession;

    private String redirectUrl = "/";

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException {

        // 1) userId 확보
        String userId = (authentication != null) ? authentication.getName() : null;

        // 2) 세션ID 확보: invalidate 전에 session.getId()를 최우선으로
        HttpSession session = request.getSession(false);

        String sessionId = null;
        if (session != null) {
            sessionId = session.getId();
        } else {
            // 세션이 이미 없으면, 쿠키 기반으로라도 요청이 가진 세션ID 확보 가능
            sessionId = request.getRequestedSessionId();
        }
        if (sessionId == null || sessionId.trim().isEmpty()) {
            sessionId = "N/A";
        }

        // 3) 여기서 직접 invalidate (XML에서 invalidate-session="false"로 두는 전제)
        if (session != null) {
            try { session.invalidate(); } catch (Exception ignore) {}
        }

        // 4) 로그 기록
        if (userId != null && !userId.trim().isEmpty()) {
            Map<String, Object> param = new HashMap<>();
            param.put("userId", userId);
            param.put("logType", "LOGOUT");
            param.put("logContent", "LOGOUT success (session=" + sessionId + ")");
            sqlSession.insert("security.insertUserLog", param);
        }

        // 5) 리다이렉트
        String target = (redirectUrl == null || redirectUrl.isEmpty()) ? "/" : redirectUrl;
        response.sendRedirect(request.getContextPath() + target);
    }
}
