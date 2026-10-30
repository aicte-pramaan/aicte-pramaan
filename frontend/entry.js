/* AICTE-PRAMAAN role entry gate. Load after app.js. */
(function () {
    "use strict";

    var ROLES = [
        { id: "audit", title: "Audit Officer", desc: "Review the hash-chained audit trail and vigilance alerts.", access: "lock" },
        { id: "aicte", title: "AICTE Admin", desc: "Manage the registry, data ingestion, quotas and analytics.", access: "lock" },
        { id: "institution", title: "Institution Officer", desc: "Upload admissions and track your institution's seat intake.", access: "lock" },
        { id: "employer", title: "Employee Verifier", desc: "Check a student's record and print a verified certificate.", access: "open" }
    ];
    var ACCESS = {
        lock: { text: "Demo two-step sign-in", icon: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>' },
        open: { text: "No sign-in needed", icon: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>' }
    };

    function chakra() {
        var svg = '<circle cx="100" cy="100" r="94" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="100" cy="100" r="11" fill="currentColor"/>';
        for (var i = 0; i < 24; i++) {
            var a = i * Math.PI / 12, x = Math.cos(a), y = Math.sin(a);
            svg += '<line x1="' + (100 + 16*x).toFixed(2) + '" y1="' + (100 + 16*y).toFixed(2) + '" x2="' + (100 + 82*x).toFixed(2) + '" y2="' + (100 + 82*y).toFixed(2) + '" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>';
        }
        return svg;
    }

    var CSS = [
        "#entry-gate{position:fixed;inset:0;z-index:9000;display:flex;flex-direction:column;overflow-y:auto;background:#f7f7f4;color:#151a2c;-webkit-font-smoothing:antialiased;font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
        "#entry-gate[hidden]{display:none}#entry-gate *{box-sizing:border-box}#entry-gate .eg-flag{height:3px;background:linear-gradient(90deg,#d9791a 0 33.34%,#fff 33.34% 66.67%,#1e6b45 66.67% 100%)}",
        "#entry-gate .eg-wrap{position:relative;z-index:1;flex:1;display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:60px;align-items:center;width:100%;max-width:1080px;margin:0 auto;padding:66px 36px 30px}",
        "#entry-gate .eg-brand{display:flex;align-items:center;gap:12px;color:#23398a}#entry-gate .eg-brand svg{width:38px;height:38px}#entry-gate .eg-name{font-size:15px;font-weight:600;color:#151a2c}",
        "#entry-gate h1{margin:34px 0 0;max-width:420px;font:600 42px/1.14 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-lede{margin:18px 0 0;max-width:400px;font-size:16px;line-height:1.6;color:#4d556b}#entry-gate .eg-ver{margin:34px 0 0;font:12px 'IBM Plex Mono',monospace;color:#6b7186}",
        "#entry-gate .eg-panel{background:#fff;border:1px solid #d9d9d2;border-radius:6px;overflow:hidden}#entry-gate .eg-panel h2{margin:0;padding:22px 28px 16px;font:600 20px 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-list{list-style:none;margin:0;padding:0}",
        "#entry-gate .eg-row{position:relative;display:flex;align-items:center;gap:18px;width:100%;padding:18px 26px;background:transparent;border:0;border-top:1px solid #e6e6e0;text-align:left;cursor:pointer;font:inherit;color:inherit}#entry-gate .eg-row:hover{background:#f5f7fc}#entry-gate .eg-row:focus-visible{outline:2px solid #23398a;outline-offset:-2px}",
        "#entry-gate .eg-info{flex:1;min-width:0}#entry-gate .eg-t{display:block;font:600 19px 'Source Serif 4',Georgia,serif;color:#101a33}#entry-gate .eg-d{display:block;margin-top:3px;font-size:14px;line-height:1.5;color:#5d6479}#entry-gate .eg-acc{display:flex;align-items:center;gap:6px;white-space:nowrap;font-size:12px}#entry-gate .eg-acc svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.9}#entry-gate .eg-acc.lock{color:#23398a}#entry-gate .eg-acc.open{color:#1e6b45}",
        "#entry-gate .eg-foot{padding:18px 30px 24px;text-align:center;font-size:12px;color:#6b7186}#entry-gate .eg-chakra{position:fixed;right:-210px;bottom:-230px;width:700px;height:700px;color:#23398a;opacity:.06;pointer-events:none}",
        "#entry-switch{position:fixed;right:16px;bottom:16px;z-index:800;padding:8px 14px;border-radius:6px;cursor:pointer;font:500 13px 'IBM Plex Sans',sans-serif;color:#23398a;background:#fff;border:1px solid #d9d9d2}#entry-switch[hidden]{display:none}",
        "@media(max-width:900px){#entry-gate .eg-wrap{grid-template-columns:1fr;gap:30px;padding:54px 22px 24px}#entry-gate h1{font-size:32px;margin-top:24px}#entry-gate .eg-ver{margin-top:20px}}",
        "@media(max-width:560px){#entry-gate .eg-row{flex-wrap:wrap;gap:6px 12px;padding:16px 20px}#entry-gate .eg-acc{width:100%}#entry-gate .eg-panel h2{padding:19px 20px 14px}}",
        "@media(prefers-reduced-motion:reduce){#entry-gate *{animation:none!important;transition:none!important}}"
    ].join("");

    var gate, switchBtn, waiting = false;
    function loadFonts() {
        if (document.getElementById("entry-gate-fonts")) return;
        var link = document.createElement("link");
        link.id = "entry-gate-fonts"; link.rel = "stylesheet";
        link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400&family=IBM+Plex+Sans:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,600&display=swap";
        document.head.appendChild(link);
    }
    function show() {
        waiting = false; gate.hidden = false; switchBtn.hidden = true;
        document.documentElement.style.overflow = "hidden"; gate.focus({ preventScroll: true });
    }
    function hide() {
        gate.hidden = true; switchBtn.hidden = false; document.documentElement.style.overflow = "";
    }
    function cancelSelection() {
        waiting = false;
        var modal = document.getElementById("m-2fa");
        if (modal) modal.classList.add("hidden");
        if (!gate.hidden) gate.focus({ preventScroll: true });
    }
    function openTwoFactor() {
        var modal = document.getElementById("m-2fa");
        if (!modal) {
            waiting = false;
            if (typeof window.showToast === "function") window.showToast("Sign-in unavailable", "The two-step sign-in dialog is missing.", "danger");
            return;
        }
        modal.style.zIndex = "10000"; modal.classList.remove("hidden");
        var otp = document.querySelector(".otp-input"); if (otp) otp.focus();
    }
    function choose(role) {
        waiting = true;
        if (role === "employer") {
            var select = document.getElementById("role"); if (select) select.value = role;
            if (typeof window.applyRole === "function") window.applyRole(role);
            return;
        }
        if (typeof pendingRole !== "undefined") pendingRole = role;
        openTwoFactor();
    }
    function build() {
        loadFonts();
        var style = document.createElement("style"); style.id = "entry-gate-styles"; style.textContent = CSS; document.head.appendChild(style);
        gate = document.createElement("div"); gate.id = "entry-gate"; gate.tabIndex = -1;
        gate.setAttribute("role", "dialog"); gate.setAttribute("aria-modal", "true"); gate.setAttribute("aria-labelledby", "eg-title");
        var rows = ROLES.map(function (role) {
            var access = ACCESS[role.access];
            return '<li><button type="button" class="eg-row" data-role="' + role.id + '"><span class="eg-info"><span class="eg-t">' + role.title + '</span><span class="eg-d">' + role.desc + '</span></span><span class="eg-acc ' + role.access + '"><svg viewBox="0 0 24 24" aria-hidden="true">' + access.icon + '</svg>' + access.text + '</span></button></li>';
        }).join("");
        gate.innerHTML = '<div class="eg-flag"></div><svg class="eg-chakra" viewBox="0 0 200 200" aria-hidden="true">' + chakra() + '</svg><div class="eg-wrap"><section><div class="eg-brand"><svg viewBox="0 0 200 200" aria-hidden="true">' + chakra() + '</svg><span class="eg-name">AICTE-PRAMAAN</span></div><h1 id="eg-title">Admission records, verified end to end.</h1><p class="eg-lede">Every record is signed and added to a tamper-evident ledger. Choose your role to continue.</p><p class="eg-ver">Version 1.4.2-PROD · demo environment</p></section><section class="eg-panel"><h2>Select your role</h2><ul class="eg-list">' + rows + '</ul></section></div><div class="eg-foot">Government of India · Ministry of Education</div>';
        document.body.appendChild(gate);
        switchBtn = document.createElement("button"); switchBtn.id = "entry-switch"; switchBtn.type = "button"; switchBtn.textContent = "Switch role"; switchBtn.hidden = true; document.body.appendChild(switchBtn);
        gate.addEventListener("click", function (event) { var row = event.target.closest(".eg-row"); if (row) choose(row.getAttribute("data-role")); });
        switchBtn.addEventListener("click", function () {
            if (typeof jwtToken !== "undefined") jwtToken = "";
            if (typeof jwtRole !== "undefined") jwtRole = "";
            show();
        });
    }
    function init() {
        if (typeof applyRole !== "function") { console.warn("entry.js: app.js must load first."); return; }
        build();
        var original = applyRole;
        applyRole = function () {
            var result = original.apply(this, arguments);
            if (waiting && (arguments[0] === "employer" || (typeof jwtToken !== "undefined" && jwtToken))) {
                waiting = false; hide();
            }
            return result;
        };
        window.cancelEntryRoleSelection = cancelSelection;
        window.showEntryGate = show;
        show();
    }
    init();
})();
