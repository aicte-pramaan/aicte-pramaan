/* AICTE-PRAMAAN role entry gate.
 * Load after app.js. Role changes integrate with the backend JWT login flow.
 */
(function () {
    "use strict";

    var ROLES = [
        { id: "audit", title: "Audit Officer", desc: "Review the hash-chained audit trail and vigilance alerts.", access: "lock" },
        { id: "aicte", title: "AICTE Admin", desc: "Manage the registry, data ingestion, quotas and analytics.", access: "lock" },
        { id: "institution", title: "Institution Officer", desc: "Upload admissions and track your institution's seat intake.", access: "lock" },
        { id: "employer", title: "Employee Verifier", desc: "Check a student's record and print a verified certificate.", access: "open" }
    ];

    var ACCESS = {
        lock: { text: "Two-step sign-in", icon: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>' },
        open: { text: "No sign-in needed", icon: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>' }
    };

    var CSS = [
        "#entry-gate{position:fixed;inset:0;z-index:9000;display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;background:#f7f7f4;color:#151a2c;-webkit-font-smoothing:antialiased;font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
        "#entry-gate[hidden]{display:none}#entry-gate *{box-sizing:border-box;min-width:0}#entry-gate .eg-flag{height:3px;flex:none;background:linear-gradient(90deg,#d9791a 0 33.34%,#fff 33.34% 66.67%,#1e6b45 66.67% 100%)}",
        "#entry-gate .eg-wrap{position:relative;z-index:1;flex:1;display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:60px;align-items:center;width:100%;max-width:1080px;margin:0 auto;padding:66px 36px 30px}",
        "#entry-gate .eg-brand{display:flex;align-items:center;gap:12px;color:#23398a}#entry-gate .eg-logo{width:46px;height:46px;flex:none;object-fit:contain;background:#fff;border-radius:8px;padding:2px;border:1px solid #e4e4dc}#entry-gate .eg-name{font-size:15px;font-weight:600;color:#151a2c;letter-spacing:.04em}",
        "#entry-gate h1{margin:34px 0 0;max-width:420px;font:600 42px/1.14 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-lede{margin:18px 0 0;max-width:400px;font-size:16px;line-height:1.6;color:#4d556b;overflow-wrap:anywhere}#entry-gate .eg-ver{margin:34px 0 0;font:12px 'IBM Plex Mono',monospace;color:#6b7186}",
        "#entry-gate .eg-panel{background:#fff;border:1px solid #d9d9d2;border-radius:6px;overflow:hidden;min-width:0}#entry-gate .eg-panel h2{margin:0;padding:22px 28px 16px;font:600 20px 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-list{list-style:none;margin:0;padding:0}",
        "#entry-gate .eg-row{position:relative;display:flex;align-items:center;gap:18px;width:100%;padding:18px 26px;background:transparent;border:0;border-top:1px solid #e6e6e0;text-align:left;cursor:pointer;font:inherit;color:inherit}#entry-gate .eg-row:hover{background:#f5f7fc}#entry-gate .eg-row:focus-visible{outline:2px solid #23398a;outline-offset:-2px}",
        "#entry-gate .eg-info{flex:1;min-width:0}#entry-gate .eg-t{display:block;font:600 19px 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-d{display:block;margin-top:3px;font-size:14px;line-height:1.5;color:#5d6479;overflow-wrap:anywhere}#entry-gate .eg-acc{display:flex;align-items:center;gap:6px;white-space:normal;font-size:12px;flex:none}#entry-gate .eg-acc svg{width:15px;height:15px;flex:none;fill:none;stroke:currentColor;stroke-width:1.9}#entry-gate .eg-acc.lock{color:#23398a}#entry-gate .eg-acc.open{color:#1e6b45}",
        "#entry-gate .eg-go{width:16px;height:16px;flex:none;fill:none;stroke:#9aa1b4;stroke-width:2}#entry-gate .eg-foot{padding:18px 30px 24px;text-align:center;font-size:12px;color:#6b7186}#entry-gate .eg-chakra{position:absolute;right:-210px;bottom:-230px;width:700px;height:700px;color:#23398a;opacity:.055;pointer-events:none}",
        "#entry-switch{position:fixed;right:16px;bottom:16px;z-index:800;padding:8px 14px;border-radius:6px;cursor:pointer;font:500 13px 'IBM Plex Sans',sans-serif;color:#23398a;background:#fff;border:1px solid #d9d9d2;box-shadow:0 3px 12px rgba(0,0,0,.12)}#entry-switch[hidden]{display:none}",
        "@media(max-width:900px){#entry-gate .eg-wrap{grid-template-columns:1fr;gap:30px;align-items:start;padding:54px 22px 24px}#entry-gate h1{font-size:32px;margin-top:24px}#entry-gate .eg-ver{margin-top:20px}#entry-gate .eg-chakra{width:500px;height:500px}}",
        "@media(max-width:560px){#entry-gate .eg-wrap{gap:24px;padding:42px 14px 18px}#entry-gate h1{font-size:29px;line-height:1.18}#entry-gate .eg-panel h2{padding:18px 16px 13px}#entry-gate .eg-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px 10px;padding:15px 16px}#entry-gate .eg-info{grid-column:1/-1}#entry-gate .eg-acc{grid-column:1;justify-self:start;font-size:11px}#entry-gate .eg-go{grid-column:2;grid-row:2;justify-self:end}#entry-gate .eg-foot{padding:14px 14px 22px;font-size:11px}#entry-switch{right:12px;bottom:12px}}",
        "@media(max-width:360px){#entry-gate .eg-row{padding:13px 12px}#entry-gate .eg-t{font-size:17px}#entry-gate .eg-d{font-size:12.5px}}",
        "@media(prefers-reduced-motion:reduce){#entry-gate *{animation:none!important;transition:none!important}}"
    ].join("");

    var gate = null;
    var switchBtn = null;
    var waiting = false;

    function loadFonts() {
        if (document.getElementById("entry-gate-fonts")) return;
        var link = document.createElement("link");
        link.id = "entry-gate-fonts";
        link.rel = "stylesheet";
        link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400&family=IBM+Plex+Sans:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,600&display=swap";
        document.head.appendChild(link);
    }

    function setEntryHistory(mode) {
        var url = new URL(window.location.href);
        url.hash = "entry";
        var next = `${url.pathname}${url.search}${url.hash}`;
        if (mode === "push") {
            window.history.pushState({ aictePage: "entry" }, "", next);
        } else if (mode === "replace") {
            window.history.replaceState({ aictePage: "entry" }, "", next);
        }
    }

    function show(historyMode) {
        if (!gate || !switchBtn) return;
        waiting = false;
        var modal = document.getElementById("m-2fa");
        if (modal) modal.classList.add("hidden");
        gate.hidden = false;
        switchBtn.hidden = true;
        document.documentElement.style.overflow = "hidden";
        if (historyMode === "push" || historyMode === "replace") setEntryHistory(historyMode);
        gate.focus({ preventScroll: true });
    }

    function hide() {
        if (!gate || !switchBtn) return;
        gate.hidden = true;
        switchBtn.hidden = false;
        document.documentElement.style.overflow = "";
    }

    function cancelSelection() {
        waiting = false;
        document.querySelectorAll(".otp-input").forEach(function (input) { input.value = ""; });
        if (window.location.hash === "#signin") {
            window.history.back();
            return;
        }
        var modal = document.getElementById("m-2fa");
        if (modal) modal.classList.add("hidden");
        if (gate && !gate.hidden) gate.focus({ preventScroll: true });
    }

    function beginSignInHistoryStep() {
        if (window.location.hash === "#signin") return;
        var url = new URL(window.location.href);
        url.hash = "signin";
        window.history.pushState({ aictePage: "signin" }, "", `${url.pathname}${url.search}${url.hash}`);
    }

    function completeSignInHistoryStep() {
        if (window.location.hash !== "#signin") return;
        var url = new URL(window.location.href);
        url.hash = "entry";
        window.history.replaceState({ aictePage: "entry" }, "", `${url.pathname}${url.search}${url.hash}`);
    }

    function openTwoFactor(recordHistory) {
        // Wake a sleeping Render instance while the user enters the OTP.
        // This request is non-blocking; the login POST remains authoritative.
        if (typeof window.warmAicteBackend === "function") {
            var status = document.getElementById("signin-status");
            if (status) status.textContent = "Connecting to the AICTE backend while you enter the code…";
            window.warmAicteBackend().then(function (reachable) {
                var currentStatus = document.getElementById("signin-status");
                var currentModal = document.getElementById("m-2fa");
                if (currentStatus && currentModal && !currentModal.classList.contains("hidden")) {
                    currentStatus.textContent = reachable
                        ? "Backend is reachable. Enter demo code 123456 to continue."
                        : "Backend warm-up did not respond; sign-in will still attempt the login request.";
                }
            });
        }
        var modal = document.getElementById("m-2fa");
        if (!modal) {
            waiting = false;
            if (typeof window.showToast === "function") window.showToast("Sign-in unavailable", "The two-step sign-in dialog is missing.", "danger");
            return;
        }
        if (recordHistory !== false) beginSignInHistoryStep();
        if (typeof window.setPendingAuthRole === "function" && typeof pendingRole !== "undefined") {
            window.setPendingAuthRole(pendingRole);
        }
        modal.style.zIndex = "10000";
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
        var otp = document.querySelector(".otp-input");
        if (otp) otp.focus();
    }

    function choose(role) {
        waiting = true;
        if (role === "employer") {
            var select = document.getElementById("role");
            if (select) select.value = role;
            var applied = typeof window.applyRole === "function" && window.applyRole(role) === true;
            if (applied) completeRoleSelection(role);
            return;
        }
        if (typeof window.setPendingAuthRole === "function") {
            window.setPendingAuthRole(role);
        } else if (typeof pendingRole !== "undefined") {
            pendingRole = role;
        }
        openTwoFactor();
    }

    function completeRoleSelection(role) {
        var isEmployer = role === "employer";
        var authenticated = typeof jwtToken !== "undefined" && !!jwtToken &&
            typeof jwtRole !== "undefined" &&
            ((role === "institution" && jwtRole === "INSTITUTION") ||
             ((role === "aicte" || role === "audit") && jwtRole === "AICTE"));
        if (!isEmployer && !authenticated) return false;

        waiting = false;
        var modal = document.getElementById("m-2fa");
        if (modal) {
            modal.classList.add("hidden");
            modal.setAttribute("aria-hidden", "true");
        }
        hide();
        return true;
    }

    function build() {
        loadFonts();
        var style = document.createElement("style");
        style.id = "entry-gate-styles";
        style.textContent = CSS;
        document.head.appendChild(style);

        gate = document.createElement("div");
        gate.id = "entry-gate";
        gate.tabIndex = -1;
        gate.setAttribute("role", "dialog");
        gate.setAttribute("aria-modal", "true");
        gate.setAttribute("aria-labelledby", "eg-title");

        var rows = ROLES.map(function (role) {
            var access = ACCESS[role.access];
            return '<li><button type="button" class="eg-row" data-role="' + role.id + '">' +
                '<span class="eg-info"><span class="eg-t">' + role.title + '</span><span class="eg-d">' + role.desc + '</span></span>' +
                '<span class="eg-acc ' + role.access + '"><svg viewBox="0 0 24 24" aria-hidden="true">' + access.icon + '</svg>' + access.text + '</span>' +
                '<svg class="eg-go" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>' +
                '</button></li>';
        }).join("");

        gate.innerHTML =
            '<div class="eg-flag"></div>' +
            '<svg class="eg-chakra" viewBox="0 0 200 200" aria-hidden="true"><circle cx="100" cy="100" r="94" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="100" cy="100" r="11" fill="currentColor"/></svg>' +
            '<div class="eg-wrap">' +
                '<section>' +
                    '<div class="eg-brand"><img class="eg-logo" src="assets/aicte-logo.svg" alt="AICTE-inspired emblem"><span class="eg-name">AICTE-PRAMAAN</span></div>' +
                    '<h1 id="eg-title">Admission records, verified end to end.</h1>' +
                    '<p class="eg-lede">Every record is signed and added to a tamper-evident ledger. Choose your role to continue.</p>' +
                    '<p class="eg-ver">Version 1.4.2-PROD · demo environment</p>' +
                '</section>' +
                '<section class="eg-panel"><h2>Select your role</h2><ul class="eg-list">' + rows + '</ul></section>' +
            '</div>' +
            '<div class="eg-foot">Government of India · Ministry of Education</div>';
        document.body.appendChild(gate);

        switchBtn = document.createElement("button");
        switchBtn.id = "entry-switch";
        switchBtn.type = "button";
        switchBtn.textContent = "Switch role";
        switchBtn.hidden = true;
        document.body.appendChild(switchBtn);

        gate.addEventListener("click", function (event) {
            var target = event.target instanceof Element ? event.target : event.target.parentElement;
            var row = target && target.closest(".eg-row");
            if (row) choose(row.getAttribute("data-role"));
        });
        switchBtn.addEventListener("click", function () {
            // Keep the current JWT until a new role is successfully selected. This
            // makes browser Back from the role chooser restore the previous page.
            show("push");
        });
    }

    function init() {
        if (typeof window.warmAicteBackend === "function") {
            window.warmAicteBackend();
        }
        if (typeof window.applyRole !== "function") {
            console.warn("entry.js: app.js must load first.");
            return;
        }
        build();

        // Keep role activation and entry-screen dismissal as separate explicit
        // steps. The previous applyRole monkey-patch could leave the OTP modal
        // open even after the backend had issued a valid JWT.
        window.completeEntryRoleSelection = completeRoleSelection;
        window.cancelEntryRoleSelection = cancelSelection;
        window.showEntryGate = function () { show("pop"); };
        window.hideEntryGate = hide;
        window.beginEntrySignInStep = beginSignInHistoryStep;
        window.completeEntrySignInStep = completeSignInHistoryStep;
        window.showEntrySignIn = function () { openTwoFactor(false); };

        window.addEventListener("popstate", function () {
            if (window.location.hash === "#entry") {
                show("pop");
            } else if (window.location.hash === "#signin") {
                // Forward returns to the OTP modal without adding another history step.
                openTwoFactor(false);
            } else {
                var modal = document.getElementById("m-2fa");
                if (modal) modal.classList.add("hidden");
                hide();
            }
        });

        // On a fresh load, start at the role-selection step. A later role selection
        // adds its own hash entry, making Back return to this step.
        show("replace");
    }

    init();
})();
