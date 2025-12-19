package com.enjoybt.framework.security.controller;

import com.enjoybt.framework.config.Constants;
import com.enjoybt.framework.security.encoder.RSAGenerator;
import com.enjoybt.framework.security.service.SecurityService;
import com.enjoybt.framework.security.util.ResultHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;
import java.util.HashMap;
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
}
