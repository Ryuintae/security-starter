package com.enjoybt.framework.security.service;

import com.enjoybt.framework.security.vo.UserVO;

import java.util.Map;

public interface SecurityService {

    /* =====================
     * 회원가입
     * ===================== */
    void signupUser(Map<String, Object> request) throws Exception;

    /* =====================
     * 로그인
     * ===================== */
    UserVO loadUserByUserId(String userId) throws Exception;

    void increaseLoginFailCnt(String userId) throws Exception;

    void resetLoginFailCnt(String userId) throws Exception;

    Map<String, Object> checkDuplicateId(String userId) throws Exception;

}
