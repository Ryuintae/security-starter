/* =========================
 * auth_fetch.js  (API 전용)
 * - RSA 키 발급/암호화 헬퍼 제공
 * ========================= */
(function () {
    const CTX = (window.CTX || "/").replace(/\/+$/, "");

    async function postNoBody(path) {
        const url = `${CTX}${path}`;
        const res = await fetch(url, {
            method: "POST",
            credentials: "same-origin",
        });
        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`POST ${url} failed: ${res.status} ${text}`);
        }
        return res.json();
    }

    async function postJson(path, body) {
        const url = `${CTX}${path}`;
        const res = await fetch(url, {
            method: "POST",
            credentials: "same-origin",
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
        const data = await postNoBody("/security/getPasswordEncoder.do");
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
    // Security APIs
    // =========================
    function checkDuplicateId(userId) {
        return postJson("/security/checkDuplicateID.do", { user_id: userId });
    }

    function signup(payload) {
        return postJson("/security/signup.do", payload);
    }

    function changePassword(payload) {
        return postJson("/security/changePassword.do", payload);
    }

    // =========================
    // Region APIs
    // =========================
    function regionSido() {
        return postNoBody("/security/region/sido.do");
    }

    function regionSigungu(sidoCd) {
        return postJson("/security/region/sigungu.do", { sido_cd: sidoCd });
    }

    function regionUmd(sidoCd, sigunguCd) {
        return postJson("/security/region/umd.do", { sido_cd: sidoCd, sigungu_cd: sigunguCd });
    }

    // =========================
    // Logout API
    // =========================
    function logout() {
        return fetch(`${CTX}/security/logout.do`, {
            method: "POST",
            credentials: "same-origin",
        });
    }

    window.SECURITY_API = {
        // low-level
        postNoBody,
        postJson,
        // rsa
        fetchRsaKey,
        encryptWithRsa,
        // auth
        checkDuplicateId,
        signup,
        changePassword,
        logout,
        // region
        regionSido,
        regionSigungu,
        regionUmd,
        // misc
        CTX,
    };
})();
