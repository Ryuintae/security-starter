package com.enjoybt.framework.security;

import com.enjoybt.framework.config.Constants;
import com.enjoybt.framework.database.CommonDAO;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 *  Description : HttpSession을 관리하는 리스너
 */
public class CustomHttpSessionListener implements HttpSessionListener {

	/* 로그 관리 객체 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomHttpSessionListener.class);
	
	/* (non-Javadoc)
	 * @see javax.servlet.http.HttpSessionListener#sessionCreated(javax.servlet.http.HttpSessionEvent)
	 */
	@Override
	public void sessionCreated(HttpSessionEvent se) {
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("===================== Session Create!! = " + se.getSession().getId() + " ===================== ");
		}
		se.getSession().setMaxInactiveInterval(Constants.SESSION_TIMEOUT);
	}

	/* (non-Javadoc)
	 * @see javax.servlet.http.HttpSessionListener#sessionDestroyed(javax.servlet.http.HttpSessionEvent)
	 */
	@Override
	public void sessionDestroyed(HttpSessionEvent se) {
		HttpSession session = se.getSession();
		String userId = (String) session.getAttribute("userId");
		String reason = (String) session.getAttribute("LOGOUT_REASON"); // "USER" or null

		// 세션 정리
		session.removeAttribute("userId");
		session.removeAttribute("userVO");

		if (StringUtils.isBlank(userId)) return;

		String logType = "LOGOUT";
		String content;

		if ("USER".equals(reason)) {
			content = "LOGOUT by user (session=" + session.getId() + ")";
		} else {
			content = "LOGOUT by timeout (session=" + session.getId() + ")";
		}

		try {
			Map<String, Object> param = new HashMap<>();
			param.put("userId", userId);
			param.put("logType", logType);
			param.put("logContent", content);

			ServletContext servletContext = session.getServletContext();
			WebApplicationContext appContext =
					WebApplicationContextUtils.getWebApplicationContext(servletContext);

			CommonDAO mainDAO = (CommonDAO) appContext.getBean("mainDAO");
			mainDAO.insert("security.insertUserLog", param);

		} catch (SQLException e) {
			LOGGER.error("Logout Error", e);
		}
	}
}
