/* AICTE-PRAMAAN entry page: role selection (v2 design).
 * Load AFTER app.js:  <script src="app.js"></script><script src="entry.js"></script>
 * Builds its own markup and styles, and hooks into the existing
 * 2FA modal (#m-2fa), pendingRole, jwtToken and applyRole().
 */
(function () {
    "use strict";

    var ROLES = [
        { id: "audit", title: "Audit Officer",
          desc: "Review the hash-chained audit trail and vigilance alerts.", access: "lock" },
        { id: "aicte", title: "AICTE Admin",
          desc: "Manage the registry, data ingestion, quotas and analytics.", access: "lock" },
        { id: "institution", title: "Institution Officer",
          desc: "Upload admissions and track your institution's seat intake.", access: "lock" },
        { id: "employer", title: "Employee Verifier",
          desc: "Check a student's record and print a verified certificate.", access: "open" }
    ];

    var ACCESS = {
        lock: { text: "Two-step sign-in",
                icon: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>' },
        open: { text: "No sign-in needed",
                icon: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>' }
    };

    // 24-spoke wheel, drawn once and reused for the emblem and the watermark.
    function chakra() {
        var s = '<circle cx="100" cy="100" r="94" fill="none" stroke="currentColor" stroke-width="4"/>' +
                '<circle cx="100" cy="100" r="11" fill="currentColor"/>';
        for (var i = 0; i < 24; i++) {
            var a = i * Math.PI / 12, c = Math.cos(a), n = Math.sin(a);
            s += '<line x1="' + (100 + 16 * c).toFixed(2) + '" y1="' + (100 + 16 * n).toFixed(2) +
                 '" x2="' + (100 + 82 * c).toFixed(2) + '" y2="' + (100 + 82 * n).toFixed(2) +
                 '" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>' +
                 '<circle cx="' + (100 + 88 * Math.cos(a + Math.PI / 24)).toFixed(2) +
                 '" cy="' + (100 + 88 * Math.sin(a + Math.PI / 24)).toFixed(2) + '" r="2.6" fill="currentColor"/>';
        }
        return s;
    }

    var CSS = [
        "#entry-gate{position:fixed;inset:0;z-index:9000;display:flex;flex-direction:column;overflow-y:auto;",
        "background:#f7f7f4;color:#151a2c;-webkit-font-smoothing:antialiased;",
        "font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
        "#entry-gate[hidden]{display:none}",
        "#entry-gate *{box-sizing:border-box}",
        "#entry-gate:focus{outline:none}",
        "#entry-gate .eg-flag{position:absolute;top:0;left:0;right:0;height:3px;z-index:3;",
        "background:linear-gradient(90deg,#d9791a 0 33.34%,#ffffff 33.34% 66.67%,#1e6b45 66.67% 100%);",
        "box-shadow:0 1px 0 #d9d9d2}",
        "#entry-gate .eg-chakra{position:absolute;right:-200px;bottom:-220px;width:760px;height:760px;",
        "color:#23398a;opacity:.07;pointer-events:none;animation:eg-spin 240s linear infinite}",
        "@keyframes eg-spin{to{transform:rotate(360deg)}}",

        "#entry-gate .eg-wrap{position:relative;z-index:1;flex:1;display:grid;",
        "grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:72px;align-items:center;",
        "width:100%;max-width:1080px;margin:0 auto;padding:72px 40px 32px}",

        "#entry-gate .eg-brand{display:flex;align-items:center;gap:12px;color:#23398a}",
        "#entry-gate .eg-brand svg{width:38px;height:38px;flex:none}",
        "#entry-gate .eg-name{font-size:15px;font-weight:600;letter-spacing:.04em;color:#151a2c}",
        "#entry-gate h1{margin:36px 0 0;max-width:420px;font-family:'Source Serif 4',Georgia,'Times New Roman',serif;",
        "font-size:42px;line-height:1.14;font-weight:600;letter-spacing:-.01em;color:#101a33}",
        "#entry-gate .eg-lede{margin:18px 0 0;max-width:400px;font-size:16px;line-height:1.6;color:#4d556b}",
        "#entry-gate .eg-ver{margin:40px 0 0;font-family:'IBM Plex Mono',ui-monospace,Menlo,monospace;font-size:12px;color:#6b7186}",

        "#entry-gate .eg-panel{background:#fff;border:1px solid #d9d9d2;border-radius:6px;overflow:hidden}",
        "#entry-gate .eg-panel h2{margin:0;padding:22px 28px 16px;font-family:'Source Serif 4',Georgia,serif;",
        "font-size:20px;font-weight:600;color:#101a33}",
        "#entry-gate .eg-list{list-style:none;margin:0;padding:0}",
        "#entry-gate .eg-row{position:relative;display:flex;align-items:center;gap:20px;width:100%;",
        "padding:18px 28px;background:transparent;border:0;border-top:1px solid #e6e6e0;text-align:left;",
        "cursor:pointer;font:inherit;color:inherit;transition:background .15s}",
        "#entry-gate .eg-row:before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:#d9791a;",
        "transform:scaleY(0);transition:transform .15s}",
        "#entry-gate .eg-row:hover{background:#f5f7fc}",
        "#entry-gate .eg-row:hover:before,#entry-gate .eg-row:focus-visible:before{transform:scaleY(1)}",
        "#entry-gate .eg-row:focus-visible{outline:2px solid #23398a;outline-offset:-2px}",
        "#entry-gate .eg-info{flex:1;min-width:0}",
        "#entry-gate .eg-t{display:block;font-family:'Source Serif 4',Georgia,serif;font-size:19px;font-weight:600;color:#101a33}",
        "#entry-gate .eg-d{display:block;margin-top:3px;font-size:14px;line-height:1.5;color:#5d6479}",
        "#entry-gate .eg-acc{flex:none;display:flex;align-items:center;gap:6px;font-size:13px;font-weight:500;white-space:nowrap}",
        "#entry-gate .eg-acc svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.9;",
        "stroke-linecap:round;stroke-linejoin:round}",
        "#entry-gate .eg-acc.lock{color:#23398a}",
        "#entry-gate .eg-acc.open{color:#1e6b45}",
        "#entry-gate .eg-go{flex:none;width:16px;height:16px;fill:none;stroke:#9aa1b4;stroke-width:2;",
        "stroke-linecap:round;stroke-linejoin:round;transition:stroke .15s}",
        "#entry-gate .eg-row:hover .eg-go{stroke:#23398a}",

        "#entry-gate .eg-foot{position:relative;z-index:1;padding:20px 40px 26px;text-align:center;",
        "font-size:12.5px;color:#6b7186}",

        "#entry-switch{position:fixed;right:16px;bottom:16px;z-index:800;padding:8px 14px;border-radius:6px;cursor:pointer;",
        "font:500 13px 'IBM Plex Sans',system-ui,sans-serif;color:#23398a;background:#fff;border:1px solid #d9d9d2}",
        "#entry-switch:hover{background:#f5f7fc;border-color:#23398a}",
        "#entry-switch:focus-visible{outline:2px solid #23398a;outline-offset:2px}",
        "#entry-switch[hidden]{display:none}",

        "@media (max-width:900px){",
        "#entry-gate .eg-wrap{grid-template-columns:1fr;gap:36px;align-items:start;padding:56px 22px 24px}",
        "#entry-gate h1{font-size:32px;margin-top:26px}",
        "#entry-gate .eg-ver{margin-top:24px}",
        "#entry-gate .eg-chakra{width:520px;height:520px;right:-180px;bottom:-160px}",
        "}",
        "@media (max-width:560px){",
        "#entry-gate .eg-row{flex-wrap:wrap;gap:6px 12px;padding:16px 20px}",
        "#entry-gate .eg-acc{order:3;width:100%}",
        "#entry-gate .eg-go{display:none}",
        "#entry-gate .eg-panel h2{padding:20px 20px 14px}",
        "}",
        "@media (prefers-reduced-motion:reduce){#entry-gate .eg-chakra{animation:none}",
        "#entry-gate .eg-row,#entry-gate .eg-row:before{transition:none}}"
    ].join("");

    var gate, switchBtn, waiting = false;

    function loadFonts() {
        if (document.getElementById("entry-gate-fonts")) return;
        var link = document.createElement("link");
        link.id = "entry-gate-fonts";
        link.rel = "stylesheet";
        link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400&family=IBM+Plex+Sans:wght@400;500;600" +
                    "&family=Source+Serif+4:opsz,wght@8..60,600&display=swap";
        document.head.appendChild(link);
    }

    function build() {
        loadFonts();
        var style = document.createElement("style");
        style.id = "entry-gate-styles";
        style.textContent = CSS;
        document.head.appendChild(style);

        gate = document.createElement("div");
        gate.id = "entry-gate";
        gate.setAttribute("role", "dialog");
        gate.setAttribute("tabindex", "-1");
        gate.setAttribute("aria-modal", "true");
        gate.setAttribute("aria-labelledby", "eg-title");

        var wheel = chakra();
        var rows = ROLES.map(function (r) {
            var a = ACCESS[r.access];
            return '<li><button type="button" class="eg-row" data-role="' + r.id + '">' +
                '<span class="eg-info"><span class="eg-t">' + r.title + '</span>' +
                '<span class="eg-d">' + r.desc + '</span></span>' +
                '<span class="eg-acc ' + r.access + '"><svg viewBox="0 0 24 24" aria-hidden="true">' + a.icon + '</svg>' + a.text + '</span>' +
                '<svg class="eg-go" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>' +
                '</button></li>';
        }).join("");

        gate.innerHTML =
            '<div class="eg-flag"></div>' +
            '<svg class="eg-chakra" viewBox="0 0 200 200" aria-hidden="true">' + wheel + '</svg>' +
            '<div class="eg-wrap">' +
                '<section>' +
                    '<div class="eg-brand"><svg viewBox="0 0 200 200" aria-hidden="true">' + wheel + '</svg>' +
                    '<span class="eg-name">AICTE-PRAMAAN</span></div>' +
                    '<h1 id="eg-title">Admission records, verified end to end.</h1>' +
                    '<p class="eg-lede">Every record is signed and added to a tamper-evident ledger. Choose your role to continue.</p>' +
                    '<p class="eg-ver">Version 1.4.2-PROD, hosted on NIC MeghRaj</p>' +
                '</section>' +
                '<section class="eg-panel">' +
                    '<h2>Select your role</h2>' +
                    '<ul class="eg-list">' + rows + '</ul>' +
                '</section>' +
            '</div>' +
            '<div class="eg-foot">Government of India, Ministry of Education</div>';

        document.body.appendChild(gate);

        switchBtn = document.createElement("button");
        switchBtn.id = "entry-switch";
        switchBtn.type = "button";
        switchBtn.textContent = "Switch role";
        switchBtn.hidden = true;
        document.body.appendChild(switchBtn);

        gate.addEventListener("click", function (e) {
            var row = e.target.closest(".eg-row");
            if (row) choose(row.getAttribute("data-role"));
        });
        switchBtn.addEventListener("click", function () {
            if (typeof jwtToken !== "undefined") jwtToken = "";
            show();
        });
    }

    function show() {
        waiting = false;
        gate.hidden = false;
        switchBtn.hidden = true;
        document.documentElement.style.overflow = "hidden";
        gate.focus({ preventScroll: true });
    }

    function hide() {
        gate.hidden = true;
        switchBtn.hidden = false;
        document.documentElement.style.overflow = "";
    }

    function openTwoFactor() {
        var modal = document.getElementById("m-2fa");
        if (!modal) return;
        modal.style.zIndex = "10000";
        modal.classList.remove("hidden");
        var otp = document.querySelector(".otp-input");
        if (otp) otp.focus();
    }

    function choose(role) {
        waiting = true;
        if (role === "employer") {
            // Verifier needs no login: the verify endpoints are public.
            var sel = document.getElementById("role");
            if (sel) sel.value = role;
            applyRole(role);
            return;
        }
        // Other roles sign in through the existing 2FA modal.
        if (typeof pendingRole !== "undefined") pendingRole = role;
        openTwoFactor();
    }

    function init() {
        if (typeof applyRole !== "function") {
            console.warn("entry.js: app.js must load first.");
            return;
        }
        build();

        // Close the gate once the app actually applies a role.
        var original = applyRole;
        applyRole = function () {
            var out = original.apply(this, arguments);
            if (waiting) { waiting = false; hide(); }
            return out;
        };

        show();
        window.showEntryGate = show;
    }

    init();
})();