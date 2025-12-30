# Security Starter

Spring 기반 프로젝트에서 **공통으로 재사용 가능한 로그인·회원가입 보안 인증 모듈**입니다.  
RSA 암호화, 로그인 실패 제어, 세션 로그 관리 등 **실서비스에 바로 적용 가능한 인증 기능**을 포함합니다.
<img width="1330" height="766" alt="image" src="https://github.com/user-attachments/assets/b4d7bba2-157b-4165-b0dd-5d242352a6fc" />

---

## 목차

1. 프로젝트 개요  
2. 주요 기능  
3. 프로젝트 구조  
   - 백엔드 구조  
   - 프론트엔드 구조  
4. 인증 흐름 요약  
5. 기술 스택  
6. 실행 및 참고 사항  

---

## 1. 프로젝트 개요

**Security Starter**는 사내 여러 서비스에서 공통으로 사용할 수 있도록 구성된  
Spring + Spring Security 기반의 인증/보안 스타터 프로젝트입니다.

- 로그인 / 회원가입 / 비밀번호 변경 / 아이디 찾기 제공  
- RSA 기반 비밀번호 암호화 적용  
- 로그인 실패 횟수 누적 및 계정 잠금 처리  
- 로그인·로그아웃 시 세션 로그 기록  

---

## 2. 주요 기능

- 로그인 5회 실패 시 계정 잠금  
- RSA 기반 비밀번호 암호화  
- 회원가입 시 ID 중복 확인  
- 회원가입 시 지역 선택 및 읍·면·동 코드 저장  
- 비밀번호 변경 기능  
- 로그인 / 로그아웃 시 세션 로그 저장  
- 이메일 또는 전화번호 기반 아이디 찾기  

---

## 3. 프로젝트 구조

### 3-1. 백엔드 (Spring / Java)
```
src/main/java
└─ com.enjoybt.framework
├─ config
│ └─ Constants.java
├─ database
│ └─ CommonDAO.java
└─ security
├─ controller
│ ├─ SecurityController.java
│ └─ SecurityRestController.java
├─ encoder
│ ├─ RSAGenerator.java
│ ├─ CustomStandardPasswordEncoder.java
│ └─ Digester.java
├─ service
│ ├─ SecurityService.java
│ └─ impl
│ └─ SecurityServiceImpl.java
├─ util
│ ├─ SecurityEncoder.java
│ ├─ UserUtil.java
│ └─ ResultHashMap.java
├─ vo
│ └─ UserVO.java
├─ CustomUserNamePassword.java
├─ LoginHandler.java
├─ CustomLogoutSuccessHandler.java
└─ CustomHttpSessionListener.java

```


---

### 3-2. 프론트엔드 (JSP / JavaScript)
```
src/main/webapp
├─ WEB-INF
│ ├─ views
│ │ └─ index.jsp
│ └─ config
│ └─ dispatcher-servlet.xml
├─ resources
│ ├─ css
│ │ └─ auth.css
│ └─ js
│ ├─ lib
│ │ └─ rsa
│ │ ├─ jsbn.js
│ │ ├─ rsa.js
│ │ ├─ prng4.js
│ │ └─ rng.js
│ └─ user
│ ├─ auth.js
│ └─ auth_fetch.js

```

---

## 4. 인증 흐름 요약

1. 로그인 화면 진입 시 RSA 공개키 발급  
2. 클라이언트에서 비밀번호 RSA 암호화  
3. `/security/loginProcess.do` 로 로그인 요청  
4. Spring Security 커스텀 인증 필터 처리  
5. 로그인 성공/실패에 따라 세션 및 로그 관리  

---

## 5. 기술 스택

- Java 8+
- Spring Framework
- Spring Security
- JSP / JSTL
- JavaScript (Fetch API)
- RSA 암호화
- MyBatis
- PostgreSQL

---

## 6. 실행 및 참고 사항

- 본 프로젝트는 **공통 사내 로그인 템플릿** 용도로 설계되었습니다.
- 실제 서비스 적용 시:
  - 사용자 테이블 스키마
  - 로그 테이블 구조
  - 권한(Role) 정책  
  에 맞게 일부 커스터마이징이 필요합니다.

---

### 참고

- 로그인 필터: `CustomUserNamePassword`
- RSA 키 생성: `RSAGenerator`
- 로그인/로그아웃 로그: `CustomLogoutSuccessHandler`, `CustomHttpSessionListener`
