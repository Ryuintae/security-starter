/* =========================
 * auth.js (UI 전용)
 * - DOM 접근/이벤트 바인딩/모달 제어
 * - API 호출은 window.SECURITY_API만 사용
 * - RSA 발급은 "액션 직전" (login/signup/changePw)마다 수행
 * ========================= */
(function () {
    const api = window.SECURITY_API;
    const CTX = api?.CTX || (window.CTX || "").replace(/\/+$/, "");
    const $ = (id) => document.getElementById(id);

    // ===== DOM
    const backdrop = $("backdrop");

    const loginModal = $("loginModal");
    const signupModal = $("signupModal");
    const changePwModal = $("changePwModal");

    const btnOpenLogin = $("btnOpenLogin");
    const btnLogout = $("btnLogout");

    const loginMsg = $("loginMsg");
    const signupMsg = $("signupMsg");
    const dupMsg = $("dupMsg");
    const changePwMsg = $("changePwMsg");

    const btnOpenChangePw = $("btnOpenChangePw");
    const loginForm = $("loginForm");

    const findIdModal = $("findIdModal");
    const findIdMsg = $("findIdMsg");

    // region selects
    const selSido = $("selSido");
    const selSigungu = $("selSigungu");
    const selUmd = $("selUmd");

    // ===== state
    let dupOk = false;

    // ===== modal helpers
    function openModal(modalEl){
        document.body.classList.add("modal-open");
        backdrop?.classList.add("is-open");
        modalEl?.classList.add("is-open");
    }

    function closeAll(){
        document.body.classList.remove("modal-open");
        backdrop?.classList.remove("is-open");
        loginModal?.classList.remove("is-open");
        signupModal?.classList.remove("is-open");
        changePwModal?.classList.remove("is-open");
        findIdModal?.classList.remove("is-open");
    }

    function setMsg(el, text, ok) {
        if (!el) return;
        el.textContent = text || "";
        el.classList.remove("ok", "err");
        if (text) el.classList.add(ok ? "ok" : "err");
    }

    function setDupOk(ok, message) {
        dupOk = !!ok;
        if (!dupMsg) return;

        dupMsg.textContent = message || "";
        dupMsg.setAttribute("data-ok", ok ? "Y" : "N");

        dupMsg.classList.remove("ok", "err");
        if (message) dupMsg.classList.add(ok ? "ok" : "err");
    }

    function showLogin() {
        setMsg(signupMsg, "", true);
        setDupOk(false, "");
        signupModal?.classList.remove("is-open");
        openModal(loginModal);
        $("loginUserId")?.focus();
    }

    async function showSignup() {
        setMsg(loginMsg, "", true);
        loginModal?.classList.remove("is-open");
        openModal(signupModal);
        $("signupUserId")?.focus();
        await loadSido().catch(console.error);
    }

    function showChangePw() {
        setMsg(changePwMsg, "", true);
        if ($("curPw")) $("curPw").value = "";
        if ($("newPw")) $("newPw").value = "";
        if ($("newPw2")) $("newPw2").value = "";
        openModal(changePwModal);
        $("curPw")?.focus();
    }

    // ===== RSA helper
    async function encryptOnce(rawPassword) {
        const { publicM, publicE } = await api.fetchRsaKey(); // 세션에 privateKey 세팅
        return api.encryptWithRsa(publicM, publicE, rawPassword);
    }

    // ===== region UI loaders
    async function loadSido() {
        if (!selSido) return;

        selSido.innerHTML = `<option value="">시/도 선택</option>`;
        if (selSigungu) {
            selSigungu.innerHTML = `<option value="">시/군/구 선택</option>`;
            selSigungu.disabled = true;
        }
        if (selUmd) {
            selUmd.innerHTML = `<option value="">읍/면/동 선택</option>`;
            selUmd.disabled = true;
        }

        const data = await api.regionSido();
        const list = data?.list || [];
        list.forEach((r) => {
            const opt = document.createElement("option");
            opt.value = String(r.sido_cd).trim();
            opt.textContent = String(r.sido_nm ?? "").trim();
            selSido.appendChild(opt);
        });
    }

    async function loadSigungu(sidoCd) {
        if (!selSigungu) return;

        selSigungu.innerHTML = `<option value="">시/군/구 선택</option>`;
        selSigungu.disabled = true;
        if (selUmd) {
            selUmd.innerHTML = `<option value="">읍/면/동 선택</option>`;
            selUmd.disabled = true;
        }

        if (!sidoCd) return;

        const data = await api.regionSigungu(sidoCd);
        const list = data?.list || [];
        list.forEach((r) => {
            const opt = document.createElement("option");
            opt.value = String(r.sigungu_cd).trim();
            opt.textContent = String(r.sigungu_nm ?? "").trim();
            selSigungu.appendChild(opt);
        });
        selSigungu.disabled = false;
    }

    async function loadUmd(sidoCd, sigunguCd) {
        if (!selUmd) return;

        selUmd.innerHTML = `<option value="">읍/면/동 선택</option>`;
        selUmd.disabled = true;

        if (!sidoCd || !sigunguCd) return;

        const data = await api.regionUmd(sidoCd, sigunguCd);
        const list = data?.list || [];
        list.forEach((r) => {
            const opt = document.createElement("option");
            opt.value = String(r.umd_cd).trim();
            opt.textContent = String(r.umd_nm ?? "").trim();
            selUmd.appendChild(opt);
        });
        selUmd.disabled = false;
    }

    // ===== handlers
    function onClickOpenLogin() {
        openModal(loginModal);
        $("loginUserId")?.focus();
    }

    async function onDupCheck() {
        const userId = (($("signupUserId")?.value) || "").trim();
        if (!userId) {
            setDupOk(false, "아이디를 입력하세요.");
            return;
        }

        try {
            const data = await api.checkDuplicateId(userId);
            const dup = String(data?.dup_yn || "").trim().toUpperCase();

            if (dup === "N") setDupOk(true, "사용 가능한 아이디입니다.");
            else if (dup === "Y") setDupOk(false, "이미 사용 중인 아이디입니다.");
            else {
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

        const email = (($("signupEmail")?.value) || "").trim();
        const userTel = (($("signupUserTel")?.value) || "").trim();
        const groupName = (($("signupGroupName")?.value) || "").trim();
        const userAddr = (($("signupAddr")?.value) || "").trim();
        const userAddrDt = (($("signupAddrDt")?.value) || "").trim();
        const userZcode = (($("signupZcode")?.value) || "").trim();

        const sidoCd = (selSido?.value || "").trim();
        const sigunguCd = (selSigungu?.value || "").trim();
        const umdCd = (selUmd?.value || "").trim();
        const regionUmdCd = umdCd || null; // 예: '660'

        if (!userId || !userPw || !userName) {
            setMsg(signupMsg, "아이디/비밀번호/이름을 모두 입력하세요.", false);
            return;
        }
        if (!dupOk) {
            setMsg(signupMsg, "아이디 중복확인을 완료하세요.", false);
            return;
        }

        try {
            // 액션 직전 키 발급 + 암호화
            const encPw = await encryptOnce(userPw);
            const selSigungu = $("selSigungu");

            // 시군구명 지역 추가
            const sigunguNm = selSigungu?.selectedIndex > 0
                ? selSigungu.options[selSigungu.selectedIndex].textContent.trim()
                : null;

            const sidoCd = (($("selSido")?.value) || "").trim();       // "11"
            const sigunguCd = (($("selSigungu")?.value) || "").trim(); // "250"
            const umdCd = (($("selUmd")?.value) || "").trim();         // "660"

            // 8자리 생성
            const regionUmdCd = (sidoCd && sigunguCd && umdCd)
                ? `${sidoCd}${sigunguCd}${umdCd}`   // "11250660"
                : null;

            const payload = {
                user_id: userId,
                user_pass: encPw,
                user_name: userName,

                group_name: groupName || null,
                user_tel: userTel || null,
                user_addr: userAddr || null,
                user_addr_dt: userAddrDt || null,
                user_zcode: userZcode || null,
                email: email || null,
                sgg_nm: sigunguNm,
                region_umd_cd: regionUmdCd,
            };

            const data = await api.signup(payload);

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
            // 키 발급 + 암호화
            const encPw = await encryptOnce(pw);

            if (!loginForm) {
                setMsg(loginMsg, "loginForm이 없습니다. hidden form 구성이 필요합니다.", false);
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

    async function onChangePassword() {
        const cur = (($("curPw")?.value) || "").trim();
        const nw1 = (($("newPw")?.value) || "").trim();
        const nw2 = (($("newPw2")?.value) || "").trim();

        if (!cur || !nw1 || !nw2) {
            setMsg(changePwMsg, "필수 항목을 모두 입력하세요.", false);
            return;
        }
        if (nw1 !== nw2) {
            setMsg(changePwMsg, "새 비밀번호가 일치하지 않습니다.", false);
            return;
        }
        if (cur === nw1) {
            setMsg(changePwMsg, "새 비밀번호는 현재 비밀번호와 달라야 합니다.", false);
            return;
        }

        try {
            // 변경도 액션 직전 키 발급(한 번) + 두 번 암호화
            const { publicM, publicE } = await api.fetchRsaKey();
            const encCur = api.encryptWithRsa(publicM, publicE, cur);
            const encNew = api.encryptWithRsa(publicM, publicE, nw1);

            const data = await api.changePassword({
                current_pass: encCur,
                new_pass: encNew,
            });

            const success =
                (data?.result && String(data.result).toLowerCase() === "success") ||
                (data?.RESULT && String(data.RESULT).toUpperCase() === "SUCCESS");

            if (success) {
                setMsg(changePwMsg, data?.message || "비밀번호가 변경되었습니다. 다시 로그인 해주세요.", true);

                setTimeout(async () => {
                    try { await api.logout(); } catch (e) {}
                    location.href = CTX + "/";
                }, 800);
            } else {
                setMsg(changePwMsg, data?.message || "비밀번호 변경 실패", false);
                console.error("changePassword response:", data);
            }
        } catch (e) {
            setMsg(changePwMsg, "비밀번호 변경 중 오류", false);
            console.error(e);
        }
    }

    async function onLogout() {
        try {
            await api.logout();
            location.href = CTX + "/";
        } catch (e) {
            console.error(e);
            location.href = CTX + "/";
        }
    }

    function showFindId() {
        setMsg(findIdMsg, "", true);
        loginModal?.classList.remove("is-open");
        openModal(findIdModal);
        $("findName")?.focus();
    }

    async function onFindId() {
        const name = (($("findName")?.value) || "").trim();
        const email = (($("findEmail")?.value) || "").trim();
        const tel = (($("findTel")?.value) || "").trim();

        if (!name) {
            setMsg(findIdMsg, "이름을 입력하세요.", false);
            return;
        }
        if (!email && !tel) {
            setMsg(findIdMsg, "이메일 또는 전화번호 중 하나를 입력하세요.", false);
            return;
        }

        try {
            const data = await api.findId({ user_name: name, email: email || null, user_tel: tel || null });
            const ok =
                (data?.result && String(data.result).toLowerCase() === "success") ||
                (data?.RESULT && String(data.RESULT).toUpperCase() === "SUCCESS");

            if (!ok) {
                setMsg(findIdMsg, data?.message || "조회에 실패했습니다.", false);
                return;
            }

            const list = data?.list || [];
            if (!list.length) {
                setMsg(findIdMsg, data?.message || "일치하는 계정을 찾지 못했습니다.", false);
                return;
            }

            // 아이디 목록 표시
            setMsg(findIdMsg, `조회된 아이디: ${list.join(", ")}`, true);
        } catch (e) {
            console.error(e);
            setMsg(findIdMsg, "조회 중 오류가 발생했습니다.", false);
        }
    }

    // ===== bind events
    backdrop?.addEventListener("click", closeAll);
    document.querySelectorAll("[data-close='true']").forEach((btn) => btn.addEventListener("click", closeAll));

    btnOpenLogin?.addEventListener("click", onClickOpenLogin);
    $("btnLogin")?.addEventListener("click", onLogin);

    $("goSignup")?.addEventListener("click", showSignup);
    $("goLogin")?.addEventListener("click", showLogin);

    $("btnDupCheck")?.addEventListener("click", onDupCheck);
    $("btnSignup")?.addEventListener("click", onSignup);

    btnOpenChangePw?.addEventListener("click", showChangePw);
    $("btnChangePw")?.addEventListener("click", onChangePassword);

    btnLogout?.addEventListener("click", onLogout);

    $("goFindId")?.addEventListener("click", showFindId);
    $("btnFindId")?.addEventListener("click", onFindId);
    // 중복확인
    $("signupUserId")?.addEventListener("input", () => setDupOk(false, ""));

    // region change
    selSido?.addEventListener("change", (e) => loadSigungu(e.target.value).catch(console.error));
    selSigungu?.addEventListener("change", (e) => {
        const sidoCd = (selSido?.value || "").trim();
        loadUmd(sidoCd, e.target.value).catch(console.error);
    });

    (function initLoginError() {
        const err = (window.LOGIN_ERROR || "").trim();
        if (!err) return;

        // 로그인 모달 열기
        openModal(loginModal);

        let msg = "로그인에 실패했습니다.";
        if (err === "BAD_CREDENTIALS") msg = "계정 정보가 일치하지 않습니다.";
        else if (err === "NO_USER") msg = "존재하지 않는 아이디입니다.";
        else if (err === "LOCKED") msg = "로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도하세요.";

        setMsg(loginMsg, msg, false);
    })();
})();
