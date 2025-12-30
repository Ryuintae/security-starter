package com.enjoybt.framework.security;

import com.enjoybt.framework.config.Constants;
import com.enjoybt.framework.security.encoder.CustomStandardPasswordEncoder;
import com.enjoybt.framework.security.util.UserUtil;
import com.enjoybt.framework.security.vo.UserVO;
import org.mybatis.spring.SqlSessionTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.annotation.PreDestroy;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;

/**
 *  Description : 로그인 관련하여 전체적으로 관리하는 핸들러
 */
public class LoginHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler, UserDetailsService, AuthenticationManager  {

	/* 로그 관리 객체 */
	private static final Logger LOGGER = LoggerFactory.getLogger(LoginHandler.class);

	/* 암호화 인코더 */
	private CustomStandardPasswordEncoder encoder = new CustomStandardPasswordEncoder("SHA-512");


	@Autowired
	@Qualifier("subSqlSession")
	private SqlSessionTemplate sqlSession;
	/* 메인페이지명 */
	private String mainPage = "/"; // 또는 "/index.jsp", "/security/login.do" 등 존재하는 경로

	private static final int MAX_FAIL = 5;

	@PreDestroy
	public void destory() {
        sqlSession.insert("security.insertAutoLogout");
    }

	/**
	 * 2. 로그인 요청 사용자 계정에 대한 정보를 가져오는 메서드
	 * @param userId(String)				- 사용자 ID
	 * @return (UserDetails)				- 사용자 객체(UserVO)
	 * @throws UsernameNotFoundException
	 */
	@SuppressWarnings("unchecked")
	@Override
	public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
		String logVal = "into Login Data " + userId;
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug(logVal);
		}
		List<GrantedAuthority> authenticate = new ArrayList<GrantedAuthority>();
		UserVO user = null;
        //TODO Security : 사용자 정보를 주입하기 위한 DB 조회 위치
        Map<String, Object> param = new HashMap<String, Object>();
        param.put("userId", userId);
        Map<String, Object> userInfo =
                (Map<String, Object>) sqlSession.selectOne("security.selectUserInfo", param);
        if(userInfo == null || !userInfo.containsKey("user_id")) {
            user = null;
        }else{
            LOGGER.debug(userInfo.toString());
            String rule = (String)userInfo.get("user_role");
            String pw = (String)userInfo.get("user_pass");
            authenticate.add(new SimpleGrantedAuthority("ROLE_"+rule));
            user = new UserVO(userId, pw, authenticate);
            user.setName((String)userInfo.get("user_name"));
            user.setGroupName((String)userInfo.get("group_name"));
            user.setLoginCnt((Integer)userInfo.get("login_cnt"));
        }
        return user;
	}

	/**
	 * 1. 로그인 사옹자 검증하는 메서드
	 * @param authentication(Authentication)		- 사용자 인증관련 객체(로그인 정보를 가지고 있음)
	 * @return (Authentication)						- 실제 적용될 인증관련 객체
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
		final String userId = authentication.getName();
		final String pwd = (String) authentication.getCredentials();

		UserDetails user = this.loadUserByUsername(userId);
		if (user == null) {
			// NO_USER는 카운트 제외
			throw new UsernameNotFoundException(Constants.LOGIN_FAILURE_NO_USER + ":" + userId);
		}

		// 현재 실패 횟수(로드 시점의 값)
		int currentCnt = 0;
		if (user instanceof UserVO) {
			Integer c = ((UserVO) user).getLoginCnt();
			currentCnt = (c == null) ? 0 : c;
		}

		// 이미 잠긴 계정이면 UI가 현재 카운트를 표시할 수 있게 cnt를 붙여서 던짐
		if (!user.isAccountNonLocked()) {
			throw new LockedException(Constants.LOGIN_FAILURE_OVER_ATTEMPT_COUNT + ":" + currentCnt);
		}

		// 비밀번호 불일치 → DB에서 카운트 증가 + 증가된 카운트를 반환받아 UI로 전달
		if (!encoder.matches(pwd, user.getPassword())) {
			int failCnt;
			try {
				Integer r = sqlSession.selectOne("security.addLoginCnt", userId);
				failCnt = (r == null) ? (currentCnt + 1) : r;
			} catch (Exception e) {
				// 카운트 증가가 실패해도 인증은 실패 처리
				throw new BadCredentialsException(Constants.LOGIN_FAILURE_NO_MATCH_PASSWORD + ":" + (currentCnt + 1));
			}

			if (failCnt >= MAX_FAIL) {
				throw new LockedException(Constants.LOGIN_FAILURE_OVER_ATTEMPT_COUNT + ":" + failCnt);
			}
			throw new BadCredentialsException(Constants.LOGIN_FAILURE_NO_MATCH_PASSWORD + ":" + failCnt);
		}
		// 성공: 리셋은 onAuthenticationSuccess()에서 처리
		return new UsernamePasswordAuthenticationToken(user, pwd, user.getAuthorities());
	}
	/**
	 * 	3-1. 로그인 성공시 리턴되는 메서드
	 * @param request(HttpServletRequest)		- 사용자 요청 객체
	 * @param response(HttpServletResponse)		- 사용자 응답 객체
	 * @param authentication(Authentication)	- 사용자 인증 정보
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException, ServletException {
		//TODO Security : 로그인 성공치 처리하기 위한 메서드
		final String userId = UserUtil.getUserId();
		HttpSession session = request.getSession();
		session.setAttribute("userId", userId);
		session.setAttribute("userVO", UserUtil.getUserVO());
		
		String loginType = (String)session.getAttribute("LOGIN_TYPE");
		
		if(loginType == null) {
            Map<String, Object> param = new HashMap<String, Object>();
            param.put("userId", userId);
            param.put("logType", "LOGIN");
			String content = "LOGIN success (session=" + session.getId() + ")";
			param.put("logContent", content);

            sqlSession.update("security.resetLoginCnt", userId);
            sqlSession.insert("security.insertUserLog", param);
        }

		String redirectUrl = (mainPage == null || mainPage.isEmpty()) ? "/" : mainPage;
		response.sendRedirect(request.getContextPath() + redirectUrl);
	}

	/**
	 *  3-2. 로그인 실패시 리턴되는 메서드
	 * @param request(HttpServletRequest)			- 사용자 요청 객체
	 * @param response(HttpServletResponse)			- 사용자 응답 객체
	 * @param exception(AuthenticationException)	- 인증 오류 객체
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void onAuthenticationFailure(final HttpServletRequest request,
										final HttpServletResponse response,
										final AuthenticationException exception)
			throws IOException, ServletException {

		String raw = (exception.getMessage() == null) ? "" : exception.getMessage();
		String[] parts = raw.split(":");
		String errMsg = parts.length > 0 ? parts[0] : "";
		String cntStr = parts.length > 1 ? parts[1] : "";

		int failCnt = 0;
		try { failCnt = Integer.parseInt(cntStr); } catch (Exception ignore) {}
		// UI에서 처리할 에러 코드
		String loginError;

		if (errMsg.contains(Constants.LOGIN_FAILURE_NO_USER)) {
			loginError = "NO_USER";
		} else if (errMsg.contains(Constants.LOGIN_FAILURE_NO_MATCH_PASSWORD)) {
			loginError = "BAD_CREDENTIALS";
		} else if (errMsg.contains(Constants.LOGIN_FAILURE_OVER_ATTEMPT_COUNT)) {
			loginError = "LOCKED";
		} else {
			loginError = "FAIL";
		}

		// 로그인 모달이 있는 페이지로 다시 보낸다.
		String redirectUrl = request.getContextPath() + (mainPage == null || mainPage.isEmpty() ? "/" : mainPage);

		if (redirectUrl.contains("?")) {
			redirectUrl += "&loginError=" + loginError;
		} else {
			redirectUrl += "?loginError=" + loginError;
		}
		// failCnt는 BAD_CREDENTIALS/LOCKED일 때만 표출
		if (failCnt > 0) {
			redirectUrl += "&failCnt=" + failCnt;
		}
		response.sendRedirect(redirectUrl);
	}

}
