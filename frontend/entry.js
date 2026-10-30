/* AICTE-PRAMAAN entry page: role selection — black minimal theme.
 * Load AFTER app.js:  <script src="app.js"></script><script src="entry.js"></script>
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
        { id: "employer", title: "Employer / Verifier",
          desc: "Verify a student record and print a certificate.", access: "open" }
    ];

    var ACCESS = {
        lock: { text: "Two-step sign-in",
                icon: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>' },
        open: { text: "No sign-in needed",
                icon: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>' }
    };

    /* 24-spoke Ashoka Chakra — drawn once for the logo mark */
    function chakra() {
        var s = '<circle cx="100" cy="100" r="90" fill="none" stroke="currentColor" stroke-width="5"/>' +
                '<circle cx="100" cy="100" r="10" fill="currentColor"/>';
        for (var i = 0; i < 24; i++) {
            var a = i * Math.PI / 12, c = Math.cos(a), n = Math.sin(a);
            s += '<line x1="' + (100 + 15 * c).toFixed(2) + '" y1="' + (100 + 15 * n).toFixed(2) +
                 '" x2="' + (100 + 80 * c).toFixed(2) + '" y2="' + (100 + 80 * n).toFixed(2) +
                 '" stroke="currentColor" stroke-width="2.8" stroke-linecap="round"/>' +
                 '<circle cx="' + (100 + 86 * Math.cos(a + Math.PI / 24)).toFixed(2) +
                 '" cy="' + (100 + 86 * Math.sin(a + Math.PI / 24)).toFixed(2) + '" r="2.8" fill="currentColor"/>';
        }
        return s;
    }

    /* ── CSS — pure black, no blues ── */
    var CSS = [
        /* Gate overlay */
        "#entry-gate{position:fixed;inset:0;z-index:9000;display:flex;flex-direction:column;overflow-y:auto;",
        "background:#0a0a0a;color:#c8c8c8;-webkit-font-smoothing:antialiased;",
        "font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
        "#entry-gate[hidden]{display:none}",
        "#entry-gate *{box-sizing:border-box}",
        "#entry-gate:focus{outline:none}",

        /* Tricolour — 2px, muted on dark */
        "#entry-gate .eg-flag{position:absolute;top:0;left:0;right:0;height:2px;z-index:3;",
        "background:linear-gradient(90deg,#c8602a 0 33.34%,rgba(255,255,255,.2) 33.34% 66.67%,#2a6e42 66.67% 100%)}",

        /* Chakra watermark — very faint */
        "#entry-gate .eg-chakra{position:absolute;right:-180px;bottom:-200px;width:700px;height:700px;",
        "color:#ffffff;opacity:.025;pointer-events:none}",

        /* Layout */
        "#entry-gate .eg-wrap{position:relative;z-index:1;flex:1;display:grid;",
        "grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:64px;align-items:center;",
        "width:100%;max-width:1040px;margin:0 auto;padding:64px 36px 28px}",

        /* Brand mark */
        "#entry-gate .eg-brand{display:flex;align-items:center;gap:11px;color:#f0f0f0}",
        "#entry-gate .eg-brand svg{width:32px;height:32px;flex:none;opacity:.7}",
        "#entry-gate .eg-name{font-size:12.5px;font-weight:700;letter-spacing:.04em;color:#f0f0f0;font-family:'IBM Plex Sans',sans-serif}",

        /* Hero text */
        "#entry-gate h1{margin:32px 0 0;max-width:400px;",
        "font-family:'Source Serif 4',Georgia,'Times New Roman',serif;",
        "font-size:38px;line-height:1.12;font-weight:600;letter-spacing:-.02em;color:#f0f0f0}",
        "#entry-gate .eg-lede{margin:16px 0 0;max-width:380px;font-size:15px;line-height:1.65;color:#888888}",
        "#entry-gate .eg-ver{margin:36px 0 0;font-family:'IBM Plex Mono',ui-monospace,Menlo,monospace;font-size:11px;color:#444444}",

        /* Role panel */
        "#entry-gate .eg-panel{background:#111111;border:1px solid #2a2a2a;border-radius:6px;overflow:hidden}",
        "#entry-gate .eg-panel h2{margin:0;padding:20px 24px 14px;",
        "font-family:'IBM Plex Sans',sans-serif;",
        "font-size:12px;font-weight:700;color:#555555;letter-spacing:.05em;text-transform:uppercase}",
        "#entry-gate .eg-list{list-style:none;margin:0;padding:0}",

        /* Role rows */
        "#entry-gate .eg-row{position:relative;display:flex;align-items:center;gap:18px;width:100%;",
        "padding:16px 24px;background:transparent;border:0;border-top:1px solid #1f1f1f;text-align:left;",
        "cursor:pointer;font:inherit;color:inherit;transition:background .12s}",
        "#entry-gate .eg-row:before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:#f0f0f0;",
        "transform:scaleY(0);transition:transform .12s}",
        "#entry-gate .eg-row:hover{background:#161616}",
        "#entry-gate .eg-row:hover:before,#entry-gate .eg-row:focus-visible:before{transform:scaleY(1)}",
        "#entry-gate .eg-row:focus-visible{outline:1px solid #383838;outline-offset:-1px}",

        "#entry-gate .eg-info{flex:1;min-width:0}",
        "#entry-gate .eg-t{display:block;font-family:'Source Serif 4',Georgia,serif;font-size:17px;font-weight:600;color:#f0f0f0}",
        "#entry-gate .eg-d{display:block;margin-top:2px;font-size:13px;line-height:1.5;color:#666666}",

        /* Access badge */
        "#entry-gate .eg-acc{flex:none;display:flex;align-items:center;gap:5px;",
        "font-size:11px;font-weight:600;white-space:nowrap;font-family:'IBM Plex Mono',monospace}",
        "#entry-gate .eg-acc svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;",
        "stroke-linecap:round;stroke-linejoin:round}",
        "#entry-gate .eg-acc.lock{color:#555555}",
        "#entry-gate .eg-acc.open{color:#5a9e6e}",

        /* Arrow */
        "#entry-gate .eg-go{flex:none;width:14px;height:14px;fill:none;stroke:#333333;stroke-width:2;",
        "stroke-linecap:round;stroke-linejoin:round;transition:stroke .12s}",
        "#entry-gate .eg-row:hover .eg-go{stroke:#888888}",

        /* Footer */
        "#entry-gate .eg-foot{position:relative;z-index:1;padding:18px 36px 24px;text-align:center;",
        "font-size:11.5px;color:#444444;font-family:'IBM Plex Mono',monospace}",

        /* Switch role button */
        "#entry-switch{position:fixed;right:14px;bottom:14px;z-index:800;padding:7px 13px;border-radius:4px;cursor:pointer;",
        "font:600 12px 'IBM Plex Sans',system-ui,sans-serif;color:#888888;background:#111111;border:1px solid #2a2a2a}",
        "#entry-switch:hover{background:#1a1a1a;border-color:#383838;color:#c8c8c8}",
        "#entry-switch:focus-visible{outline:1px solid #383838;outline-offset:2px}",
        "#entry-switch[hidden]{display:none}",

        /* Responsive */
        "@media (max-width:880px){",
        "#entry-gate .eg-wrap{grid-template-columns:1fr;gap:32px;align-items:start;padding:48px 20px 20px}",
        "#entry-gate h1{font-size:30px;margin-top:22px}",
        "#entry-gate .eg-ver{margin-top:20px}",
        "#entry-gate .eg-chakra{width:460px;height:460px;right:-150px;bottom:-130px}",
        "}",
        "@media (max-width:520px){",
        "#entry-gate .eg-row{flex-wrap:wrap;gap:5px 10px;padding:14px 18px}",
        "#entry-gate .eg-acc{order:3;width:100%}",
        "#entry-gate .eg-go{display:none}",
        "#entry-gate .eg-panel h2{padding:18px 18px 12px}",
        "#entry-gate .eg-t{font-size:15px}",
        "}",
        "@media (prefers-reduced-motion:reduce){",
        "#entry-gate .eg-row,#entry-gate .eg-row:before{transition:none}}"
    ].join("");

    var gate, switchBtn, waiting = false;

    function loadFonts() {
        if (document.getElementById("entry-gate-fonts")) return;
        var link = document.createElement("link");
        link.id = "entry-gate-fonts";
        link.rel = "stylesheet";
        link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400&family=IBM+Plex+Sans:wght@400;500;600;700" +
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
                '<span class="eg-info">' +
                    '<span class="eg-t">' + r.title + '</span>' +
                    '<span class="eg-d">' + r.desc + '</span>' +
                '</span>' +
                '<span class="eg-acc ' + r.access + '">' +
                    '<svg viewBox="0 0 24 24" aria-hidden="true">' + a.icon + '</svg>' +
                    a.text +
                '</span>' +
                '<svg class="eg-go" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>' +
                '</button></li>';
        }).join("");

        gate.innerHTML =
            '<div class="eg-flag"></div>' +
            '<svg class="eg-chakra" viewBox="0 0 200 200" aria-hidden="true">' + wheel + '</svg>' +
            '<div class="eg-wrap">' +
                '<section>' +
                    '<div class="eg-brand">' +
                        '<svg viewBox="0 0 200 200" aria-hidden="true">' + wheel + '</svg>' +
                        '<span class="eg-name">AICTE&nbsp;PRAMAAN</span>' +
                    '</div>' +
                    '<h1 id="eg-title">Admission records,<br>verified end to end.</h1>' +
                    '<p class="eg-lede">Every record is cryptographically signed and added to a tamper-evident ledger. Choose your role to continue.</p>' +
                    '<p class="eg-ver">v1.4.2-PROD &nbsp;·&nbsp; NIC MeghRaj &nbsp;·&nbsp; SIH26263</p>' +
                '</section>' +
                '<section class="eg-panel">' +
                    '<h2>Select role</h2>' +
                    '<ul class="eg-list">' + rows + '</ul>' +
                '</section>' +
            '</div>' +
            '<div class="eg-foot">Government of India &nbsp;&nbsp;Ministry of Education</div>';

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
            var sel = document.getElementById("role");
            if (sel) sel.value = role;
            applyRole(role);
            return;
        }
        if (typeof pendingRole !== "undefined") pendingRole = role;
        openTwoFactor();
    }

    function init() {
        if (typeof applyRole !== "function") {
            console.warn("entry.js: app.js must load first.");
            return;
        }
        build();

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