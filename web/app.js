// Jurassic Park visitor page.
(function () {
  function esc(v) {
    return String(v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
    });
  }

  function $(id) { return document.getElementById(id); }

  async function loadWeather() {
    var res = await fetch("/api/v1/weather");
    var w = await res.json();
    $("status-chips").innerHTML =
      "<span class=\"chip " + (w.park_open ? "ok" : "bad") + "\">" + (w.park_open ? "Park open" : "Park closed") + "</span>" +
      "<span class=\"chip\">\u26C5 " + esc(w.temperature_c) + "\u00B0C, " + esc(w.summary) + "</span>" +
      "<span class=\"chip\">Last boat " + esc(w.last_boat) + "</span>";
  }

  async function search(q) {
    var res = await fetch("/api/v1/dinosaurs?q=" + encodeURIComponent(q || ""));
    var data = await res.json();
    var results = data.results || [];
    $("dino-grid").innerHTML = results.length ? results.map(function (d) {
      return "<div class=\"card\"><div class=\"sp\">" + esc(d.species) + "</div><div class=\"nm\">" + esc(d.name) +
        "</div><div class=\"pd\">" + esc(d.paddock) + " &middot; " + esc(d.status) + "</div></div>";
    }).join("") : "<p class=\"muted\">No dinosaurs found.</p>";
  }

  function pass() { return sessionStorage.getItem("tourPass"); }

  async function loadBookings() {
    if (!pass()) { return; }
    var res = await fetch("/api/v1/bookings", { headers: { "Authorization": "Bearer " + pass() } });
    if (!res.ok) { sessionStorage.removeItem("tourPass"); return; }
    var data = await res.json();
    $("bookings").classList.remove("hidden");
    $("pass-panel").classList.add("hidden");
    $("bookings-who").textContent = "Booked for " + data.visitor;
    $("bookings-list").innerHTML = data.bookings.map(function (b) {
      return "<li><span>" + esc(b.tour) + "<br/><span class=\"muted\">" + esc(b.slot) + "</span></span>" +
        "<button class=\"small ghost\" data-booking=\"" + b.id + "\">Details</button></li>";
    }).join("");
  }

  async function showBooking(id) {
    var res = await fetch("/api/v1/bookings/" + id, { headers: { "Authorization": "Bearer " + pass() } });
    var b = await res.json();
    $("booking-detail").textContent = res.ok ? ("Booking #" + b.id + ": " + b.tour + ", " + b.slot + ". " + b.notes) : "Booking not found.";
  }

  $("search-form").addEventListener("submit", function (e) { e.preventDefault(); search($("search-input").value); });

  $("pass-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    $("pass-error").textContent = "";
    var res = await fetch("/api/v1/tour-pass", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("pass-name").value })
    });
    var data = await res.json();
    if (!res.ok) { $("pass-error").textContent = data.error; return; }
    sessionStorage.setItem("tourPass", data.tour_pass);
    loadBookings();
  });

  $("bookings-list").addEventListener("click", function (e) {
    var id = e.target.getAttribute("data-booking");
    if (id) { showBooking(id); }
  });

  loadWeather();
  search("");
  loadBookings();
})();
