<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<c:set var="ctx" value="${pageContext.request.contextPath}"/>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<!doctype html>
<html lang="ko">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>EnjoyBT - Security</title>

    <script>
        window.CTX = "${ctx}";
        window.LOGIN_ERROR = "${param.loginError}";
        window.LOGIN_FAIL_CNT = "${param.failCnt}";
    </script>

    <!-- CSS -->
    <link rel="stylesheet" href="${ctx}/resources/css/auth.css"/>

    <!-- RSA libs -->
    <script src="${ctx}/resources/js/lib/rsa/jsbn.js" defer></script>
    <script src="${ctx}/resources/js/lib/rsa/rsa.js" defer></script>
    <script src="${ctx}/resources/js/lib/rsa/prng4.js" defer></script>
    <script src="${ctx}/resources/js/lib/rsa/rng.js" defer></script>

    <!-- App scripts -->
    <script src="${ctx}/resources/js/user/auth_fetch.js" defer></script>
    <script src="${ctx}/resources/js/user/auth.js" defer></script>
</head>
<body>

<!-- 상단바: 초기에는 로그인 버튼만 노출 -->
<header class="topbar">
    <div class="topbar-inner">
        <!-- 좌측 타이틀 -->
        <div class="topbar-left">
            <h1 class="topbar-title">Security <span class="sep">-</span> Starter</h1>
        </div>

        <!-- 우측 액션 영역 -->
        <div class="topbar-right">
            <sec:authorize access="isAuthenticated()">
                <span class="welcome">
                    <sec:authentication property="name"/>님 환영합니다.
                </span>
                <button id="btnOpenChangePw" type="button" class="btn">비밀번호 변경</button>
                <button id="btnLogout" type="button" class="btn">로그아웃</button>
            </sec:authorize>

            <sec:authorize access="isAnonymous()">
                <button id="btnOpenLogin" type="button" class="btn btn--primary">로그인</button>
            </sec:authorize>
        </div>
    </div>
</header>

<div class="app">
    <section class="hero">
        <div class="hero-card">
            <h2 class="hero-title">Security Starter</h2>
            <p class="hero-desc">
                사내 서비스에서 공통으로 사용하는 RSA 기반 통합 로그인 인증 서비스입니다.
            </p>

            <div class="hero-row hero-row--inline">
                <span class="hero-tag">구현 항목</span>

                <ul class="feature-chips">
                    <li>로그인 5회 실패 계정 잠금</li>
                    <li>RSA 비밀번호 암호화</li>
                    <li>ID 중복 확인</li>
                    <li>지역 선택(읍·면·동 코드 저장)</li>
                    <li>비밀번호 변경</li>
                    <li>로그인/로그아웃 세션 로그 저장</li>
                    <li>이름/전화번호 기반 아이디 찾기</li>
                </ul>
            </div>
        </div>
    </section>
</div>

<!-- Backdrop -->
<div id="backdrop" class="backdrop"></div>

<!-- (권장) Spring Security 로그인 처리용 hidden form
     filterProcessesUrl="/security/loginProcess.do"
     usernameParameter="userID"
     passwordParameter="password"
-->
<form id="loginForm" method="post" action="<%=request.getContextPath()%>/security/loginProcess.do">
    <input type="hidden" name="userID" value=""/>
    <input type="hidden" name="password" value=""/>
</form>

<!-- Login Modal -->
<div id="loginModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="loginTitle">
    <div class="modal-header">
        <h2 id="loginTitle">로그인</h2>
        <button type="button" class="modal-close" data-close="true">×</button>
    </div>

    <div class="modal-body">
        <div class="field">
            <label for="loginUserId">아이디</label>
            <input id="loginUserId" type="text" autocomplete="username"/>
        </div>

        <div class="field">
            <label for="loginUserPw">비밀번호</label>
            <input id="loginUserPw" type="password" autocomplete="current-password"/>
        </div>

        <div class="actions">
            <button id="btnLogin" type="button" class="btn btn--primary">로그인</button>
        </div>

        <p class="switch">
            계정이 없으신가요?
            <button type="button" class="link" id="goSignup">회원가입</button>
        </p>
        <p class="switch">
            아이디를 잊으셨나요?
            <button type="button" class="link" id="goFindId">아이디 찾기</button>
        </p>
        <div id="loginMsg" class="msg" aria-live="polite"></div>
    </div>
</div>

<!-- Signup Modal -->
<div id="signupModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="signupTitle">
    <div class="modal-header">
        <h2 id="signupTitle">회원가입</h2>
        <button type="button" class="modal-close" data-close="true">×</button>
    </div>

    <div class="modal-body">
        <div class="field">
            <label for="signupUserId">아이디 <span class="req">*</span></label>
            <div class="row">
                <input id="signupUserId" type="text" autocomplete="username"/>
                <button id="btnDupCheck" type="button" class="btn">중복확인</button>
            </div>
            <div id="dupMsg" class="hint" aria-live="polite"></div>
        </div>

        <div class="field">
            <label for="signupUserPw">비밀번호 <span class="req">*</span></label>
            <input id="signupUserPw" type="password" autocomplete="new-password"/>
        </div>

        <div class="field">
            <label for="signupUserName">이름 <span class="req">*</span></label>
            <input id="signupUserName" type="text"/>
        </div>

        <div class="field">
            <label for="signupEmail">이메일</label>
            <input id="signupEmail" type="email" autocomplete="email"/>
        </div>

        <div class="field">
            <label for="signupUserTel">전화번호</label>
            <input id="signupUserTel" type="tel" placeholder="010-1234-5678"/>
        </div>

        <div class="field">
            <label for="signupGroupName">소속 기관명</label>
            <input id="signupGroupName" type="text"/>
        </div>

        <div class="field">
            <label>지역 선택</label>
            <div class="row">
                <select id="selSido" class="select">
                    <option value="">시/도 선택</option>
                </select>
                <select id="selSigungu" class="select" disabled>
                    <option value="">시/군/구 선택</option>
                </select>
                <select id="selUmd" class="select" disabled>
                    <option value="">읍/면/동 선택</option>
                </select>
            </div>
            <div class="hint">선택 시 읍면동 코드가 저장됩니다.</div>
        </div>

        <div class="field">
            <label for="signupAddr">주소</label>
            <input id="signupAddr" type="text" placeholder="기본 주소"/>
        </div>

        <div class="field">
            <label for="signupAddrDt">상세주소</label>
            <input id="signupAddrDt" type="text" placeholder="상세 주소"/>
        </div>

        <div class="field">
            <label for="signupZcode">우편번호</label>
            <input id="signupZcode" type="text"/>
        </div>

        <div class="actions">
            <button id="btnSignup" type="button" class="btn btn--primary">가입하기</button>
        </div>

        <p class="switch">
            이미 계정이 있으신가요?
            <button type="button" class="link" id="goLogin">로그인</button>
        </p>

        <div id="signupMsg" class="msg" aria-live="polite"></div>
    </div>
</div>
<!-- Change Password Modal -->
<div id="changePwModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="changePwTitle">
    <div class="modal-header">
        <h2 id="changePwTitle">비밀번호 변경</h2>
        <button type="button" class="modal-close" data-close="true">×</button>
    </div>

    <div class="modal-body">
        <div class="field">
            <label for="curPw">현재 비밀번호</label>
            <input id="curPw" type="password" autocomplete="current-password"/>
        </div>

        <div class="field">
            <label for="newPw">새 비밀번호</label>
            <input id="newPw" type="password" autocomplete="new-password"/>
        </div>

        <div class="field">
            <label for="newPw2">새 비밀번호 확인</label>
            <input id="newPw2" type="password" autocomplete="new-password"/>
        </div>

        <div class="actions">
            <button id="btnChangePw" type="button" class="btn btn--primary">변경</button>
        </div>

        <div id="changePwMsg" class="msg" aria-live="polite"></div>

        <p class="hint" style="margin-top:10px;">
            보안을 위해 변경 완료 후 자동 로그아웃됩니다.
        </p>
    </div>
</div>
<!-- Find ID Modal -->
<div id="findIdModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="findIdTitle">
    <div class="modal-header">
        <h2 id="findIdTitle">아이디 찾기</h2>
        <button type="button" class="modal-close" data-close="true">×</button>
    </div>

    <div class="modal-body">
        <div class="field">
            <label for="findName">이름</label>
            <input id="findName" type="text"/>
        </div>

        <div class="field">
            <label for="findEmail">이메일 (또는 전화번호 중 하나 필수)</label>
            <input id="findEmail" type="email" autocomplete="email"/>
        </div>

        <div class="field">
            <label for="findTel">전화번호</label>
            <input id="findTel" type="tel" placeholder="01012345678"/>
        </div>

        <div class="actions">
            <button id="btnFindId" type="button" class="btn btn--primary">조회</button>
        </div>

        <div id="findIdMsg" class="msg" aria-live="polite"></div>
    </div>
</div>
</body>
</html>
