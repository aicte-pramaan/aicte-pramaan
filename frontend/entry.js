/* AICTE-PRAMAAN entry page: role selection.
 * Load AFTER app.js:  <script src="app.js"></script><script src="entry.js"></script>
 * It builds its own markup and styles, and hooks into the existing
 * 2FA modal (#m-2fa), pendingRole, jwtToken and applyRole().
 */
(function () {
    "use strict";

    var ROLES = [
        {
            id: "audit",
            title: "Audit Officer",
            desc: "Review the hash-chained audit trail and vigilance alerts.",
            tag: "Sign-in with 2FA",
            tone: "lock",
            icon: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h4"/>'
        },
        {
            id: "aicte",
            title: "AICTE Admin",
            desc: "Manage the registry, data ingestion, quotas and analytics.",
            tag: "Sign-in with 2FA",
            tone: "lock",
            icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>'
        },
        {
            id: "institution",
            title: "Institution Officer",
            desc: "Upload admissions and track your institution's seat intake.",
            tag: "Sign-in with 2FA",
            tone: "lock",
            icon: '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18"/><path d="M2 22h20"/><path d="M10 6h4M10 10h4M10 14h4"/>'
        },
        {
            id: "employer",
            title: "Employee Verifier",
            desc: "Check a student's record and print a verified certificate.",
            tag: "No sign-in needed",
            tone: "open",
            icon: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/><path d="m8.5 11 2 2 3.5-3.5"/>'
        }
    ];

    var CSS = [
        "#entry-gate{position:fixed;inset:0;z-index:9000;display:flex;background:#f4f6fb;color:#0f172a;",
        "font-family:Inter,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;-webkit-font-smoothing:antialiased}",
        "#entry-gate[hidden]{display:none}",
        "#entry-gate *{box-sizing:border-box}",
        "#entry-gate .eg-flag{position:absolute;top:0;left:0;right:0;height:4px;z-index:2;",
        "background:linear-gradient(90deg,#f59e0b 0 33.34%,#ffffff 33.34% 66.67%,#15803d 66.67% 100%);box-shadow:0 1px 0 #e2e8f0}",

        "#entry-gate .eg-side{flex:0 0 380px;display:flex;flex-direction:column;justify-content:space-between;",
        "padding:44px 40px 32px;color:#cbd5e1;background:linear-gradient(180deg,#0b1020 0%,#10173a 100%)}",
        "#entry-gate .eg-brand{display:flex;align-items:center;gap:12px}",
        "#entry-gate .eg-logo{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;",
        "font-weight:700;font-size:20px;color:#fff;background:linear-gradient(135deg,#7c6cf0,#4f46e5)}",
        "#entry-gate .eg-name{font-size:18px;font-weight:700;color:#fff;letter-spacing:.2px}",
        "#entry-gate .eg-badge{display:inline-block;margin-top:4px;padding:2px 8px;border-radius:6px;font-size:11px;",
        "font-weight:600;color:#67e8f9;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.35)}",
        "#entry-gate .eg-pitch{margin:0;max-width:300px;font-size:26px;line-height:1.25;font-weight:650;color:#fff}",
        "#entry-gate .eg-points{list-style:none;margin:22px 0 0;padding:0;display:grid;gap:12px;font-size:14px}",
        "#entry-gate .eg-points li{display:flex;align-items:center;gap:10px}",
        "#entry-gate .eg-points li:before{content:'';width:6px;height:6px;border-radius:50%;background:#6366f1;flex:none}",
        "#entry-gate .eg-ver{font-family:'JetBrains Mono',ui-monospace,Menlo,monospace;font-size:11px;color:#64748b}",

        "#entry-gate .eg-main{flex:1;display:flex;flex-direction:column;overflow-y:auto}",
        "#entry-gate .eg-center{flex:1;display:flex;flex-direction:column;justify-content:center;",
        "width:100%;max-width:760px;margin:0 auto;padding:56px 32px 24px}",
        "#entry-gate h1{margin:0;font-size:28px;font-weight:700;letter-spacing:-.3px}",
        "#entry-gate .eg-sub{margin:8px 0 28px;font-size:15px;color:#64748b}",
        "#entry-gate .eg-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}",

        "#entry-gate .eg-card{display:flex;flex-direction:column;gap:14px;text-align:left;cursor:pointer;",
        "padding:20px;border-radius:14px;background:#fff;border:1px solid #e2e8f0;font:inherit;color:inherit;",
        "transition:border-color .15s,box-shadow .15s,transform .15s}",
        "#entry-gate .eg-card:hover{border-color:#6366f1;box-shadow:0 8px 24px rgba(79,70,229,.12);transform:translateY(-2px)}",
        "#entry-gate .eg-card:focus-visible{outline:2px solid #4f46e5;outline-offset:2px}",
        "#entry-gate .eg-card:active{transform:translateY(0)}",
        "#entry-gate .eg-ico{width:42px;height:42px;border-radius:10px;display:grid;place-items:center;",
        "color:#4f46e5;background:#eef2ff}",
        "#entry-gate .eg-ico svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;",
        "stroke-linecap:round;stroke-linejoin:round}",
        "#entry-gate .eg-t{font-size:16px;font-weight:650}",
        "#entry-gate .eg-d{margin-top:4px;font-size:13.5px;line-height:1.5;color:#64748b}",
        "#entry-gate .eg-tag{align-self:flex-start;margin-top:auto;padding:3px 9px;border-radius:999px;font-size:12px;font-weight:600}",
        "#entry-gate .eg-tag.lock{color:#4338ca;background:#eef2ff}",
        "#entry-gate .eg-tag.open{color:#047857;background:#ecfdf5}",

        "#entry-gate .eg-foot{padding:16px 32px 24px;text-align:center;font-size:12px;color:#94a3b8}",
        "#entry-switch{position:fixed;right:16px;bottom:16px;z-index:800;padding:8px 14px;border-radius:999px;cursor:pointer;",
        "font:600 13px Inter,system-ui,sans-serif;color:#4338ca;background:#fff;border:1px solid #c7d2fe;",
        "box-shadow:0 4px 14px rgba(15,23,42,.12)}",
        "#entry-switch:hover{background:#eef2ff}",
        "#entry-switch:focus-visible{outline:2px solid #4f46e5;outline-offset:2px}",
        "#entry-switch[hidden]{display:none}",

        "@media (max-width:860px){",
        "#entry-gate{flex-direction:column;overflow-y:auto}",
        "#entry-gate .eg-side{flex:none;padding:28px 24px 22px}",
        "#entry-gate .eg-pitch,#entry-gate .eg-points{display:none}",
        "#entry-gate .eg-ver{margin-top:14px}",
        "#entry-gate .eg-main{overflow:visible}",
        "#entry-gate .eg-center{padding:28px 20px 12px;justify-content:flex-start}",
        "}",
        "@media (max-width:560px){#entry-gate .eg-grid{grid-template-columns:1fr}#entry-gate h1{font-size:24px}}",
        "@media (prefers-reduced-motion:reduce){#entry-gate .eg-card{transition:none}#entry-gate .eg-card:hover{transform:none}}"
    ].join("");

    var gate, switchBtn, waiting = false;

    function build() {
        var style = document.createElement("style");
        style.id = "entry-gate-styles";
        style.textContent = CSS;
        document.head.appendChild(style);

        gate = document.createElement("div");
        gate.id = "entry-gate";
        gate.setAttribute("role", "dialog");
        gate.setAttribute("aria-modal", "true");
        gate.setAttribute("aria-labelledby", "eg-title");

        var cards = ROLES.map(function (r) {
            return '<button type="button" class="eg-card" data-role="' + r.id + '">' +
                '<span class="eg-ico"><svg viewBox="0 0 24 24" aria-hidden="true">' + r.icon + '</svg></span>' +
                '<span><span class="eg-t">' + r.title + '</span>' +
                '<span class="eg-d" style="display:block">' + r.desc + '</span></span>' +
                '<span class="eg-tag ' + r.tone + '">' + r.tag + '</span>' +
                '</button>';
        }).join("");

        gate.innerHTML =
            '<div class="eg-flag"></div>' +
            '<aside class="eg-side">' +
                '<div>' +
                    '<div class="eg-brand"><div class="eg-logo">A</div>' +
                    '<div><div class="eg-name">AICTE-PRAMAAN</div><span class="eg-badge">SEAT-PASS SYSTEM</span></div></div>' +
                '</div>' +
                '<div>' +
                    '<p class="eg-pitch">Admission records you can verify, not just trust.</p>' +
                    '<ul class="eg-points">' +
                        '<li>Every record is signed with Ed25519</li>' +
                        '<li>Merkle proofs show nothing was altered</li>' +
                        '<li>Students control who can verify them</li>' +
                    '</ul>' +
                '</div>' +
                '<div class="eg-ver">v1.4.2-PROD (NIC MeghRaj)</div>' +
            '</aside>' +
            '<main class="eg-main">' +
                '<div class="eg-center">' +
                    '<h1 id="eg-title">Choose your role</h1>' +
                    '<p class="eg-sub">Select how you want to use the dashboard.</p>' +
                    '<div class="eg-grid">' + cards + '</div>' +
                '</div>' +
                '<div class="eg-foot">Government of India, Ministry of Education. Hosted on NIC Cloud (MeghRaj), Pune.</div>' +
            '</main>';

        document.body.appendChild(gate);

        switchBtn = document.createElement("button");
        switchBtn.id = "entry-switch";
        switchBtn.type = "button";
        switchBtn.textContent = "Switch role";
        switchBtn.hidden = true;
        document.body.appendChild(switchBtn);

        gate.addEventListener("click", function (e) {
            var card = e.target.closest(".eg-card");
            if (card) choose(card.getAttribute("data-role"));
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
        var first = gate.querySelector(".eg-card");
        if (first) first.focus();
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
