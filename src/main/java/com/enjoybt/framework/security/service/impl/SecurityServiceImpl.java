package com.enjoybt.framework.security.service.impl;

import com.enjoybt.framework.security.service.SecurityService;
import com.enjoybt.framework.security.util.SecurityEncoder;
import com.enjoybt.framework.security.vo.UserVO;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SecurityServiceImpl implements SecurityService {

    private static final String SECURITY_MAPPER = "security.";

    @Autowired
    @Qualifier("subSqlSession")
    private SqlSessionTemplate sqlSession;

    private final SecurityEncoder encoder = new SecurityEncoder();

    @Override
    public void signupUser(Map<String, Object> request) throws Exception {

        String rawPw = (String) request.get("user_pass"); // 컨트롤러에서 복호화된 평문이 들어옴
        String encPw = encoder.encode(rawPw);
        request.put("user_pass", encPw);

        request.put("user_role", "USER");
        request.put("login_cnt", 0);
        request.put("view_yn", true);
        request.put("approval_yn", true);

        sqlSession.insert(SECURITY_MAPPER + "insertUserInfo", request);
    }

    @Override
    public UserVO loadUserByUserId(String userId) throws Exception {

        Map<String, Object> param = new HashMap<>();
        param.put("userId", userId);

        // CommonDAO -> SqlSessionTemplate
        Map<String, Object> userMap =
                (Map<String, Object>) sqlSession.selectOne(
                        SECURITY_MAPPER + "selectUserInfo",
                        param
                );

        if (userMap == null) return null;

        String role = (String) userMap.get("user_role");

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        UserVO user = new UserVO(
                (String) userMap.get("user_id"),
                (String) userMap.get("user_pass"),
                authorities
        );

        user.setUserInfo(userMap);
        user.setLoginCnt((Integer) userMap.get("login_cnt"));

        return user;
    }

    @Override
    public void increaseLoginFailCnt(String userId) throws Exception {
        // CommonDAO -> SqlSessionTemplate
        sqlSession.update(SECURITY_MAPPER + "addLoginCnt", userId);
    }

    @Override
    public void resetLoginFailCnt(String userId) throws Exception {
        // CommonDAO -> SqlSessionTemplate
        sqlSession.update(SECURITY_MAPPER + "resetLoginCnt", userId);
    }

    @Override
    public Map<String, Object> checkDuplicateId(String userId) throws Exception {
        Map<String, Object> p = new HashMap<>();
        p.put("user_id", userId);

        // CommonDAO -> SqlSessionTemplate
        return (Map<String, Object>) sqlSession.selectOne(
                SECURITY_MAPPER + "checkDupID",
                p
        );
    }
    @Override
    public void changePassword(String userId, String newEncodedPassword) throws Exception {
        Map<String, Object> p = new HashMap<>();
        p.put("user_id", userId);
        p.put("user_pass", newEncodedPassword);

        sqlSession.update(SECURITY_MAPPER + "updateUserPassword", p);
    }
    @Override
    public List<Map<String, Object>> selectSidoList() throws Exception {
        return sqlSession.selectList(SECURITY_MAPPER + "selectSidoList");
    }

    @Override
    public List<Map<String, Object>> selectSigunguList(String sidoCd) throws Exception {
        Map<String, Object> p = new HashMap<>();
        p.put("sido_cd", sidoCd);
        return sqlSession.selectList(SECURITY_MAPPER + "selectSigunguList", p);
    }

    @Override
    public List<Map<String, Object>> selectUmdList(String sidoCd, String sigunguCd) throws Exception {
        Map<String, Object> p = new HashMap<>();
        p.put("sido_cd", sidoCd);
        p.put("sigungu_cd", sigunguCd);
        return sqlSession.selectList(SECURITY_MAPPER + "selectUmdList", p);
    }
}
