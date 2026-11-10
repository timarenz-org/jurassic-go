// Jurassic Park staff page.
(function () {
  var API = {
    login: "/api/v1/staff/login",
    me: "/api/v1/staff/me",
    roster: "/api/v1/staff/roster",
    exportBookings: "/api/v1/staff/bookings/export",
    feedingSchedule: "/api/v1/staff/feeding-schedule",
    power: "/api/v1/systems/power",
    fences: "/api/v1/systems/fences",
    security: "/api/v1/systems/security",
    coldStorage: "/api/v1/systems/cold-storage"
  };

  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
    });
  }
  function token() { return sessionStorage.getItem("staffToken"); }
  function api(url, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "Authorization": "Bearer " + token() }, opts.headers || {});
    return fetch(url, opts);
  }
  function post(url, body) {
    return api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }

  async function loadDashboard() {
    var res = await api(API.me);
    if (!res.ok) { sessionStorage.removeItem("staffToken"); return; }
    var me = await res.json();
    $("signin").classList.add("hidden");
    $("dashboard").classList.remove("hidden");
    $("signout").classList.remove("hidden");
    $("welcome").textContent = "Signed in as " + me.name;
    $("profile-name").value = me.name;
    $("profile-email").value = me.email;
    $("profile-role").textContent = "Role: " + me.role.replace("_", " ");

    var roster = await (await api(API.roster)).json();
    $("roster").innerHTML = roster.staff.map(function (s) {
      return "<div class=\"row\"><span>" + esc(s.name) + "</span><span class=\"muted\">" + esc(s.role.replace("_", " ")) + "</span></div>";
    }).join("");

    if (me.role === "control_room") {
      $("systems-panel").classList.remove("hidden");
      loadSystems();
    }
  }

  function toggle(label, on, onText, offText, action, offVerb, onVerb) {
    return "<div class=\"row\"><span>" + esc(label) + "</span><span>" +
      "<span class=\"chip " + (on ? "ok" : "bad") + "\">" + (on ? onText : offText) + "</span>" +
      "<button class=\"small ghost\" data-action=\"" + action + "\">" + (on ? (offVerb || "Turn off") : (onVerb || "Turn on")) + "</button></span></div>";
  }

  async function loadSystems() {
    var power = (await (await api(API.power)).json()).power;
    var fences = (await (await api(API.fences)).json()).fences;
    var security = (await (await api(API.security)).json()).security;
    var cold = (await (await api(API.coldStorage)).json()).cold_storage;
    var allArmed = Object.keys(fences).every(function (k) { return fences[k]; });
    $("systems").innerHTML =
      toggle("Main power", power === "on", "On", "Off", "power") +
      toggle("Perimeter fences", allArmed, "Armed", "Down", "fences", "Disarm", "Arm") +
      toggle("Door locks", security.door_locks, "Locked", "Unlocked", "locks", "Unlock", "Lock") +
      toggle("Cold storage door", cold.door_locked, "Locked", "Unlocked", "cold", "Unlock", "Lock") +
      "<div class=\"row\"><span>Cold storage setpoint</span><span class=\"muted\">" + esc(cold.setpoint_c) + " \u00B0C</span></div>";
    $("systems").setAttribute("data-state", JSON.stringify({ power: power, fences: allArmed, locks: security.door_locks, cold: cold.door_locked }));
  }

  async function systemsAction(action) {
    var s = JSON.parse($("systems").getAttribute("data-state") || "{}");
    var res;
    if (action === "power") { res = await post(API.power, { state: s.power === "on" ? "off" : "on" }); }
    if (action === "fences") { res = await post(API.fences, { paddock: "all", armed: !s.fences }); }
    if (action === "locks") { res = await post(API.security, { door_locks: !s.locks }); }
    if (action === "cold") { res = await post(API.coldStorage, { door_locked: !s.cold }); }
    $("systems-error").textContent = res && !res.ok ? (await res.json()).error : "";
    loadSystems();
  }

  $("signin-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    $("signin-error").textContent = "";
    var res = await fetch(API.login, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("username").value, password: $("password").value })
    });
    var data = await res.json();
    if (!res.ok) { $("signin-error").textContent = data.error; return; }
    sessionStorage.setItem("staffToken", data.token);
    loadDashboard();
  });

  $("profile-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    await api(API.me, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("profile-name").value, email: $("profile-email").value })
    });
    loadDashboard();
  });

  $("export").addEventListener("click", async function () {
    var blob = await (await api(API.exportBookings)).blob();
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "bookings.csv.zst";
    a.click();
  });

  $("schedule-import").addEventListener("click", async function () {
    var res = await api(API.feedingSchedule, { method: "POST", headers: { "Content-Type": "application/x-yaml" }, body: $("schedule").value });
    var data = await res.json();
    $("schedule-result").textContent = res.ok ? ("Imported " + data.imported + " feedings.") : data.error;
  });

  $("systems").addEventListener("click", function (e) {
    var a = e.target.getAttribute("data-action");
    if (a) { systemsAction(a); }
  });

  $("signout").addEventListener("click", function (e) {
    e.preventDefault();
    sessionStorage.removeItem("staffToken");
    location.reload();
  });

  if (token()) { loadDashboard(); }
})();
