(function () {
    const CTX = (window.CTX || "").replace(/\/+$/, "");
    const $ = (id) => document.getElementById(id);

    const btnOpenLogin = $("btnOpenLogin");

    const backdrop = $("backdrop");
    const loginModal = $("loginModal");
    const signupModal = $("signupModal");

    const loginMsg = $("loginMsg");
    const signupMsg = $("signupMsg");
    const dupMsg = $("dupMsg");

    const loginForm = document.getElementById("loginForm");

    let rsaPublicM = null;
    let rsaPublicE = null;
    let dupOk = false;

    function openModal(modalEl) {
        if (backdrop) backdrop.classList.add("is-open");
        if (modalEl) modalEl.classList.add("is-open");
    }

    function closeAll() {
        if (backdrop) backdrop.classList.remove("is-open");
        if (loginModal) loginModal.classList.remove("is-open");
        if (signupModal) signupModal.classList.remove("is-open");
    }

    function showLogin() {
        if (signupMsg) signupMsg.textContent = "";
        if (dupMsg) dupMsg.textContent = "";
        if (signupModal) signupModal.classList.remove("is-open");
        openModal(loginModal);
    }

    function showSignup() {
        if (loginMsg) loginMsg.textContent = "";
        if (loginModal) loginModal.classList.remove("is-open");
        openModal(signupModal);
    }

    function setMsg(el, text, ok) {
        if (!el) return;
        el.textContent = text || "";
        el.classList.remove("ok", "err");
        if (text) el.classList.add(ok ? "ok" : "err");
    }

    // ========== fetch helpers
    async function postNoBody(url) {
        const res = await fetch(url, { method: "POST" });
        return await res.json();
    }

    async function postJson(url, body) {
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json;charset=UTF-8" },
            body: JSON.stringify(body ?? {})
        });
        return await res.json();
    }

    // ========== RSA key load
    async function loadRsaKey() {
        try {
            // SecurityRestController는 param이 없어도 되므로 body 없이 POST가 더 안전
            const data = await postNoBody(CTX + "/security/getPasswordEncoder.do");

            // 프로젝트별로 result/RESULT가 다를 수 있어 publicM/publicE로 판단
            if (data && data.publicM && data.publicE) {
                rsaPublicM = data.publicM;
                rsaPublicE = data.publicE;
                return true;
            }
            return false;
        } catch (e) {
            return false;
        }
    }

    function encryptPassword(raw) {
        if (!raw) return "";

        if (!rsaPublicM || !rsaPublicE) {
            throw new Error("RSA public key not loaded");
        }
        if (typeof RSAKey === "undefined") {
            throw new Error("RSAKey is not defined. RSA 라이브러리를 auth.js보다 먼저 include 하세요.");
        }

        const rsa = new RSAKey();
        rsa.setPublic(rsaPublicM, rsaPublicE);
        const enc = rsa.encrypt(raw);

        if (!enc) throw new Error("RSA encrypt failed");
        return enc;
    }

    function setDupOk(ok, message) {
        dupOk = !!ok;
        if (dupMsg) {
            dupMsg.textContent = message || "";
            dupMsg.setAttribute("data-ok", ok ? "Y" : "N");
        }
    }

    // ========== handlers
    async function onClickOpenLogin() {
        // 모달 열기 전에 RSA 키가 없으면 로드 (선택)
        if (!rsaPublicM || !rsaPublicE) {
            const ok = await loadRsaKey();
            if (!ok) {
                setMsg(loginMsg, "RSA 키 발급에 실패했습니다.", false);
            }
        }
        openModal(loginModal);
    }

    async function onDupCheck() {
        const userId = (($("signupUserId")?.value) || "").trim();
        if (!userId) {
            setDupOk(false, "아이디를 입력하세요.");
            return;
        }

        try {
            const data = await postJson(CTX + "/security/checkDuplicateID.do", { user_id: userId });

            // 응답: { dup_yn: 'Y'/'N', result or RESULT ... }
            const dup = (data?.dup_yn || "").toString().trim().toUpperCase();

            if (dup === "N") {
                setDupOk(true, "사용 가능한 아이디입니다.");
            } else if (dup === "Y") {
                setDupOk(false, "이미 사용 중인 아이디입니다.");
            } else {
                setDupOk(false, "중복 확인 응답 오류");
                console.error("Unexpected dup response:", data);
            }
        } catch (e) {
            setDupOk(false, "중복 확인에 실패했습니다.");
            console.error(e);
        }
    }

    async function onSignup() {
        const userId = (($("signupUserId")?.value) || "").trim();
        const userPw = (($("signupUserPw")?.value) || "").trim();
        const userName = (($("signupUserName")?.value) || "").trim();

        if (!userId || !userPw || !userName) {
            setMsg(signupMsg, "아이디/비밀번호/이름을 모두 입력하세요.", false);
            return;
        }
        if (!dupOk) {
            setMsg(signupMsg, "아이디 중복확인을 완료하세요.", false);
            return;
        }

        try {
            if (!rsaPublicM || !rsaPublicE) {
                const ok = await loadRsaKey();
                if (!ok) {
                    setMsg(signupMsg, "RSA 키 요청 실패", false);
                    return;
                }
            }

            const encPw = encryptPassword(userPw);

            const payload = {
                user_id: userId,
                user_pass: encPw,
                user_name: userName,
                group_name: null,
                sgg_nm: null,
                user_tel: null,
                user_addr: null,
                user_addr_dt: null,
                user_zcode: null,
                email: null,
                region_umd_cd: null
            };

            const data = await postJson(CTX + "/security/signup.do", payload);

            const ok =
                (data?.result && String(data.result).toLowerCase() === "success") ||
                (data?.RESULT && String(data.RESULT).toUpperCase() === "SUCCESS");

            if (ok) {
                setMsg(signupMsg, "가입이 완료되었습니다. 로그인 해주세요.", true);
                setTimeout(showLogin, 600);
            } else {
                setMsg(signupMsg, "가입에 실패했습니다.", false);
                console.error("signup response:", data);
            }
        } catch (e) {
            setMsg(signupMsg, "가입에 실패했습니다.", false);
            console.error(e);
        }
    }

    async function onLogin() {
        const id = (($("loginUserId")?.value) || "").trim();
        const pw = (($("loginUserPw")?.value) || "").trim();

        if (!id) {
            setMsg(loginMsg, "아이디를 입력하세요.", false);
            $("loginUserId")?.focus();
            return;
        }
        if (!pw) {
            setMsg(loginMsg, "비밀번호를 입력하세요.", false);
            $("loginUserPw")?.focus();
            return;
        }

        try {
            if (!rsaPublicM || !rsaPublicE) {
                const ok = await loadRsaKey();
                if (!ok) {
                    setMsg(loginMsg, "RSA 키 요청 실패", false);
                    return;
                }
            }

            const encPw = encryptPassword(pw);

            // Spring Security custom filter:
            // filterProcessesUrl="/security/loginProcess.do"
            // usernameParameter="userID"
            // passwordParameter="password"
            if (!loginForm) {
                setMsg(loginMsg, "loginForm이 없습니다. index.jsp에 hidden form을 추가하세요.", false);
                return;
            }

            const idInput = loginForm.querySelector("input[name='userID']");
            const pwInput = loginForm.querySelector("input[name='password']");
            if (!idInput || !pwInput) {
                setMsg(loginMsg, "loginForm hidden input(name=userID/password) 구성이 필요합니다.", false);
                return;
            }

            idInput.value = id;
            pwInput.value = encPw;

            loginForm.submit();
        } catch (e) {
            setMsg(loginMsg, "로그인 처리 중 오류", false);
            console.error(e);
        }
    }

    // ========== bind events
    // 모달 닫기
    backdrop?.addEventListener("click", closeAll);
    document.querySelectorAll("[data-close='true']").forEach(btn => btn.addEventListener("click", closeAll));

    // 상단 로그인 버튼
    btnOpenLogin?.addEventListener("click", onClickOpenLogin);

    // 모달 전환
    $("goSignup")?.addEventListener("click", showSignup);
    $("goLogin")?.addEventListener("click", showLogin);

    // 아이디가 바뀌면 중복확인 다시 하도록 초기화
    $("signupUserId")?.addEventListener("input", () => setDupOk(false, ""));

    // 버튼 액션
    $("btnDupCheck")?.addEventListener("click", onDupCheck);
    $("btnSignup")?.addEventListener("click", onSignup);
    $("btnLogin")?.addEventListener("click", onLogin);
    $("btnHeroLogin")?.addEventListener("click", onClickOpenLogin);
    $("btnHeroSignup")?.addEventListener("click", showSignup);

    // ========== init
    (async function init() {
        // 초기에는 모달을 열지 않음 (요구사항)
        // RSA 키는 미리 로드해도 되고, 로그인 버튼 클릭 시 로드해도 됨.
        // 여기서는 미리 로드(실패해도 버튼 클릭 시 재시도 가능)
        await loadRsaKey();
    })();
})();
