package com.enjoybt.framework.security.controller;

import com.enjoybt.framework.config.Constants;
import com.enjoybt.framework.security.encoder.RSAGenerator;
import com.enjoybt.framework.security.service.SecurityService;
import com.enjoybt.framework.security.util.ResultHashMap;
import com.enjoybt.framework.security.util.SecurityEncoder;
import com.enjoybt.framework.security.vo.UserVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value="/security/")
public class SecurityRestController {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityRestController.class);

	@Autowired
	private SecurityService securityService;

	/** RSA 공개키 발급 (기존 그대로) */
	@RequestMapping(value="getPasswordEncoder.do", method=RequestMethod.POST)
	public Map<String, Object> createRsaSecurity(HttpServletRequest request) {
		Map<String, Object> result = new HashMap<>();
		String resultStr = Constants.VALUE_RESULT_FAILURE;
		try {
			String[] rsaEncoder = RSAGenerator.createRsaGenerator(request.getSession());
			if (rsaEncoder != null) {
				result.put("publicM", rsaEncoder[0]);
				result.put("publicE", rsaEncoder[1]);
			}
			resultStr = Constants.VALUE_RESULT_SUCCESS;
		} catch (Exception e) {
			LOGGER.error("/security/getPasswordEncoder.do Error", e);
		}

		result.put(Constants.KEY_RESULT, resultStr);
		return result;
	}

	/** 아이디 중복 확인 */
	@RequestMapping(value="checkDuplicateID.do", method=RequestMethod.POST)
	public ResultHashMap checkDuplicateID(@RequestBody Map<String, Object> body) {
		ResultHashMap result = new ResultHashMap();

		try {
			String userId = body == null ? null : (String) body.get("user_id");
			LOGGER.info("checkDuplicateID user_id={}", userId);

			if (userId == null || userId.trim().isEmpty()) {
				result.put("dup_yn", "Y"); // 또는 바로 실패처리
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				return result;
			}

			Map<String, Object> r = securityService.checkDuplicateId(userId.trim());
			result.putAll(r);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
		} catch (Exception e) {
			LOGGER.error("/security/checkDuplicateID.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
		}
		return result;
	}

	/** 회원가입 */
	@RequestMapping(value="signup.do", method=RequestMethod.POST)
	public ResultHashMap signup(HttpServletRequest request, @RequestBody Map<String, Object> req) {
		ResultHashMap result = new ResultHashMap();
		try {
			// 1) RSA 암호문 꺼내기
			String encPw = (String) req.get("user_pass");

			// 2) 세션에 저장된 PrivateKey 꺼내고(꺼내면 세션에서 제거됨)
			PrivateKey privateKey = RSAGenerator.getPrivateKey(request.getSession());

			// 3) 복호화해서 평문 비밀번호로 교체
			String rawPw = RSAGenerator.getValue(privateKey, encPw);
			req.put("user_pass", rawPw);

			// 4) 저장(서비스에서 해시 처리)
			securityService.signupUser(req);

			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
		} catch (Exception e) {
			LOGGER.error("/security/signup.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
		}
		return result;
	}
	@RequestMapping(value="changePassword.do", method=RequestMethod.POST)
	public ResultHashMap changePassword(HttpServletRequest request, @RequestBody Map<String, Object> req) {
		ResultHashMap result = new ResultHashMap();

		try {
			// 0) 로그인 사용자 ID (Spring Security)
			String userId = org.springframework.security.core.context.SecurityContextHolder
					.getContext().getAuthentication().getName();

			// 1) RSA 암호문 꺼내기
			String encCurrent = (String) req.get("current_pass");
			String encNew = (String) req.get("new_pass");

			if (encCurrent == null || encNew == null) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "필수 파라미터 누락");
				return result;
			}

			// 2) PrivateKey 꺼내고 복호화 (꺼내면 세션에서 제거)
			PrivateKey privateKey = RSAGenerator.getPrivateKey(request.getSession());

			String rawCurrent = RSAGenerator.getValue(privateKey, encCurrent);
			String rawNew = RSAGenerator.getValue(privateKey, encNew);

			// 3) 현재 사용자 정보 로드
			UserVO user = securityService.loadUserByUserId(userId);
			if (user == null) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "사용자 없음");
				return result;
			}

			// 4) 현재 비번 검증 (DB 해시 vs 입력 평문)
			// SecurityEncoder가 matches 제공하면 그걸 쓰는 게 정석
			SecurityEncoder encoder = new SecurityEncoder();
			boolean ok = encoder.matches(rawCurrent, user.getPassword()); // getPassword()가 user_pass(해시)

			if (!ok) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "현재 비밀번호가 일치하지 않습니다.");
				return result;
			}

			// 5) 새 비번 정책 검사(선택)
			if (rawNew.length() < 8) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "비밀번호는 8자 이상이어야 합니다.");
				return result;
			}

			// 6) 새 비번 해시 후 업데이트
			String newEncoded = encoder.encode(rawNew);
			securityService.changePassword(userId, newEncoded);

			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
			result.put("message", "비밀번호가 변경되었습니다.");
		} catch (Exception e) {
			LOGGER.error("/security/changePassword.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
			result.put("message", "서버 오류");
		}

		return result;
	}
	@RequestMapping(value="region/sido.do", method=RequestMethod.POST)
	public ResultHashMap regionSido() {
		ResultHashMap result = new ResultHashMap();
		try {
			result.put("list", securityService.selectSidoList());
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
		} catch (Exception e) {
			LOGGER.error("/security/region/sido.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
		}
		return result;
	}

	@RequestMapping(value="region/sigungu.do", method=RequestMethod.POST)
	public ResultHashMap regionSigungu(@RequestBody Map<String, Object> req) {
		ResultHashMap result = new ResultHashMap();
		try {
			String sidoCd = (String) req.get("sido_cd");
			result.put("list", securityService.selectSigunguList(sidoCd));
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
		} catch (Exception e) {
			LOGGER.error("/security/region/sigungu.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
		}
		return result;
	}

	@RequestMapping(value="region/umd.do", method=RequestMethod.POST)
	public ResultHashMap regionUmd(@RequestBody Map<String, Object> req) {
		ResultHashMap result = new ResultHashMap();
		try {
			String sidoCd = (String) req.get("sido_cd");
			String sigunguCd = (String) req.get("sigungu_cd");
			result.put("list", securityService.selectUmdList(sidoCd, sigunguCd));
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
		} catch (Exception e) {
			LOGGER.error("/security/region/umd.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
		}
		return result;
	}
	@RequestMapping(value="findId.do", method=RequestMethod.POST)
	public ResultHashMap findId(@RequestBody Map<String, Object> req) {
		ResultHashMap result = new ResultHashMap();

		try {
			String userName = req == null ? null : (String) req.get("user_name");
			String email = req == null ? null : (String) req.get("email");
			String userTel = req == null ? null : (String) req.get("user_tel");

			userName = (userName == null) ? null : userName.trim();
			email = (email == null) ? null : email.trim();
			userTel = (userTel == null) ? null : userTel.trim();

			if (userName == null || userName.isEmpty()) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "이름은 필수입니다.");
				return result;
			}
			if ((email == null || email.isEmpty()) && (userTel == null || userTel.isEmpty())) {
				result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
				result.put("message", "이메일 또는 전화번호 중 하나는 필수입니다.");
				return result;
			}

			List<Map<String, Object>> rows = securityService.findUserIds(userName, email, userTel);

			List<String> ids = new ArrayList<>();
			for (Map<String, Object> r : rows) {
				ids.add((String) r.get("user_id"));
			}

			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
			result.put("list", ids);
			result.put("message", ids.isEmpty() ? "일치하는 계정을 찾지 못했습니다." : "아이디 조회가 완료되었습니다.");
			return result;

		} catch (Exception e) {
			LOGGER.error("/security/findId.do Error", e);
			result.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
			result.put("message", "서버 오류");
			return result;
		}
	}
}
