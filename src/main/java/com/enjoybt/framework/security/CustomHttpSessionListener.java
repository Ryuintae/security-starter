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
		String userId = (String)se.getSession().getAttribute("userId");
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("===================== "+userId+" Session Destroy!! = " + se.getSession().getId() + " ===================== ");
		}
		//TODO Security : 세션이 종료되었을시 처리해야하는 위치
		HttpSession session = se.getSession();
		session.removeAttribute("userId");
		session.removeAttribute("userVO");
		
		if(!StringUtils.isEmpty(userId)) {
			try {
				Map<String, Object> param = new HashMap<String, Object>();
				param.put("userId", userId);
				param.put("logType", "LOGOUT");
				String content = "세션 ID("+session.getId() + ")로 로그아웃 하셨습니다.";
				param.put("logContent", content);
				ServletContext servletContext = session.getServletContext();
				WebApplicationContext appContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
				CommonDAO mainDAO = (CommonDAO)appContext.getBean("mainDAO");
				mainDAO.insert("security.insertUserLog", param);
			} catch (SQLException e) {
				if(LOGGER.isErrorEnabled()) {
					LOGGER.error("Logout Error", e);
				}
			}

		}
	}

}
