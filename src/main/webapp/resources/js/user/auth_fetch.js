(function () {
    const CTX = (window.CTX || "/").replace(/\/+$/, ""); // trailing slash 제거
    const $ = (sel) => document.querySelector(sel);

    // =========================
    // fetch helpers
    // =========================
    async function postNoBody(url) {
        const res = await fetch(url, {
            method: "POST",
            credentials: "same-origin", // 세션 유지 (JSESSIONID)
        });

        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`POST ${url} failed: ${res.status} ${text}`);
        }
        return res.json();
    }

    async function postJson(url, body) {
        const res = await fetch(url, {
            method: "POST",
            credentials: "same-origin", // 세션 유지
            headers: { "Content-Type": "application/json;charset=UTF-8" },
            body: JSON.stringify(body ?? {}),
        });

        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`POST ${url} failed: ${res.status} ${text}`);
        }
        return res.json();
    }

    // =========================
    // RSA
    // =========================
    async function fetchRsaKey() {
        // 서버: /security/getPasswordEncoder.do (POST)
        const data = await postNoBody(`${CTX}/security/getPasswordEncoder.do`);

        if (!data || !data.publicM || !data.publicE) {
            throw new Error("RSA key response missing publicM/publicE");
        }
        return { publicM: data.publicM, publicE: data.publicE, raw: data };
    }

    function encryptWithRsa(publicM, publicE, rawPassword) {
        if (typeof RSAKey === "undefined") {
            throw new Error("RSAKey is not defined. RSA 라이브러리 include 순서를 확인하세요.");
        }
        const rsa = new RSAKey();
        rsa.setPublic(publicM, publicE);
        const enc = rsa.encrypt(rawPassword);
        if (!enc) throw new Error("RSA encrypt failed");
        return enc;
    }

    // =========================
    // Login (form submit intercept)
    // =========================
    function bindLoginForm() {
        const form = $("#loginForm");
        if (!form) return;

        form.addEventListener("submit", async (e) => {
            const idEl = $("#userID");
            const pwEl = $("#pass");

            const id = (idEl?.value || "").trim();
            const pw = (pwEl?.value || "").trim();

            if (!id) {
                alert("아이디를 입력하세요.");
                idEl?.focus();
                e.preventDefault();
                return;
            }
            if (!pw) {
                alert("패스워드를 입력하세요.");
                pwEl?.focus();
                e.preventDefault();
                return;
            }

            // RSA 키 받고 암호화 후 실제 submit
            e.preventDefault();

            try {
                // 로그인 직전에 "항상" 새 키 발급 (세션 private key 소멸 문제 회피)
                const { publicM, publicE } = await fetchRsaKey();
                const encPw = encryptWithRsa(publicM, publicE, pw);

                // 서버는 name=password 파라미터를 기대(기존 코드 기준)
                const hiddenPwInput = form.querySelector("input[name='password']");
                if (!hiddenPwInput) {
                    throw new Error("loginForm에 input[name='password']가 없습니다.");
                }

                hiddenPwInput.value = encPw;

                // 평문 비번 input(#pass)은 서버로 전송되지 않게 하려면 name 제거 권장
                // pwEl.removeAttribute("name"); // 필요 시 사용

                form.submit();
            } catch (err) {
                console.error("LOGIN RSA ERROR", err);
                alert("로그인 암호화 오류");
            }
        });
    }

    // =========================
    // Duplicate check
    // =========================
    async function checkDuplicateId(userId) {
        return postJson(`${CTX}/security/checkDuplicateID.do`, { user_id: userId });
    }

    // =========================
    // Signup
    // =========================
    async function signup(req) {
        // 서버: /security/signup.do (JSON)
        return postJson(`${CTX}/security/signup.do`, req);
    }

    function bindSignup() {
        const dupBtn = $("#btnCheckDup");
        const signupBtn = $("#btnSignup");

        const dupMsg = $("#dupMsg");
        const signupMsg = $("#signupMsg");

        function setDupMsg(text, ok) {
            if (!dupMsg) return;
            dupMsg.textContent = text || "";
            dupMsg.style.color = ok ? "green" : "red";
            dupMsg.setAttribute("data-ok", ok ? "Y" : "N");
        }

        function setSignupMsg(text, ok) {
            if (!signupMsg) return;
            signupMsg.textContent = text || "";
            signupMsg.style.color = ok ? "green" : "red";
        }

        // 아이디 입력 변경 시 중복확인 무효화
        $("#su_user_id")?.addEventListener("input", () => setDupMsg("", false));

        dupBtn?.addEventListener("click", async () => {
            const userId = ($("#su_user_id")?.value || "").trim();
            if (!userId) {
                setDupMsg("아이디를 입력하세요.", false);
                return;
            }

            try {
                const res = await checkDuplicateId(userId);

                if (String(res?.RESULT || res?.result || "").toUpperCase() !== "SUCCESS") {
                    console.log("checkDuplicateID response:", res);
                    setDupMsg("중복 확인 실패(서버)", false);
                    return;
                }

                const yn = String(res?.dup_yn || "").trim().toUpperCase();
                if (yn === "N") setDupMsg("사용 가능한 아이디입니다.", true);
                else if (yn === "Y") setDupMsg("이미 사용 중인 아이디입니다.", false);
                else {
                    console.log("unexpected dup_yn:", res);
                    setDupMsg("응답 형식 오류", false);
                }
            } catch (err) {
                console.error("checkDuplicateID fail", err);
                setDupMsg("중복 확인 오류", false);
            }
        });

        signupBtn?.addEventListener("click", async () => {
            const userId = ($("#su_user_id")?.value || "").trim();
            const pw = ($("#su_user_pass")?.value || "").trim();
            const name = ($("#su_user_name")?.value || "").trim();
            const email = ($("#su_email")?.value || "").trim();

            if (!userId || !pw || !name || !email) {
                setSignupMsg("필수 항목을 모두 입력하세요.", false);
                return;
            }
            if (($("#dupMsg")?.getAttribute("data-ok") || "N") !== "Y") {
                setSignupMsg("아이디 중복확인을 완료하세요.", false);
                return;
            }

            try {
                // 회원가입 직전에 "항상" 새 키 발급
                const { publicM, publicE } = await fetchRsaKey();
                const encPw = encryptWithRsa(publicM, publicE, pw);

                const req = {
                    user_id: userId,
                    user_pass: encPw,
                    user_name: name,
                    email: email,
                };

                const res = await signup(req);

                if (String(res?.RESULT || res?.result || "").toUpperCase() === "SUCCESS") {
                    setSignupMsg("회원가입 신청 완료. 승인 후 로그인 가능합니다.", true);
                } else {
                    console.log("signup response:", res);
                    setSignupMsg("회원가입 실패", false);
                }
            } catch (err) {
                console.error("signup fail", err);
                setSignupMsg("회원가입 오류", false);
            }
        });
    }

    // =========================
    // init
    // =========================
    document.addEventListener("DOMContentLoaded", () => {
        console.log("SECURITY SCRIPT LOADED (fetch)");
        bindLoginForm();
        bindSignup();
    });
})();
