const API = "/api";

function getToken() {
  return localStorage.getItem("cc_token");
}
function setToken(t) {
  localStorage.setItem("cc_token", t);
}
function clearToken() {
  localStorage.removeItem("cc_token");
}

async function api(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const t = getToken();
    if (t) headers["Authorization"] = "Bearer " + t;
  }
  const res = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const detail = data && (data.detail || data.message);
    const msg =
      typeof detail === "string"
        ? detail
        : detail
        ? JSON.stringify(detail)
        : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

async function requireAuth(active) {
  const token = getToken();
  if (!token) {
    location.href = "/index.html";
    throw new Error("Not logged in");
  }
  try {
    const user = await api("/me");
    renderNav(active, user);
    return user;
  } catch (e) {
    clearToken();
    location.href = "/index.html";
    throw e;
  }
}

function logout() {
  const token = getToken();
  clearToken();
  fetch(API + "/logout", {
    method: "POST",
    headers: token ? { Authorization: "Bearer " + token } : {},
  }).finally(() => (location.href = "/index.html"));
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtDate(iso) {
  if (!iso) return "\u2014";
  const d = new Date(iso.replace(" ", "T") + "Z");
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function badge(status) {
  const cls =
    { "Open": "open", "In Progress": "progress", "Resolved": "resolved" }[status] || "";
  return `<span class="badge ${cls}">${esc(status)}</span>`;
}

const ICONS = {
  alert: "M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z",
  inbox: "M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z",
  plus: "M12 5v14M5 12h14",
  back: "M19 12H5M12 19l-7-7 7-7",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
};

function icon(name) {
  const d = ICONS[name] || "";
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18" aria-hidden="true"><path d="${d}"/></svg>`;
}

function stateHtml(iconName, message, btnText, href, isError = false) {
  return `<div class="empty-state">
    ${icon(iconName)}
    <p>${esc(message)}</p>
    ${btnText ? `<a class="btn ${isError ? "" : "secondary"}" href="${href}">${esc(btnText)}</a>` : ""}
  </div>`;
}

function renderNav(active, user) {
  const el = document.getElementById("nav");
  if (!el) return;
  const link = (id, href, label) =>
    `<a class="nav-link ${active === id ? "active" : ""}" href="${href}">${label}</a>`;
  el.innerHTML = `
    <div class="container nav-inner">
      <a class="brand" href="/dashboard.html">Campus<span>Connect</span></a>
      <nav class="nav-links">
        ${link("dashboard", "/dashboard.html", "Dashboard")}
        ${user && user.role === "admin" ? "" : link("create", "/create.html", "New Issue")}
        ${user ? link("messages", "/messages.html", 'Messages<span id="msg-count" class="count" hidden></span>') : ""}
        ${link("faq", "/faq.html", "FAQ")}
        ${link("profile", "/profile.html", "Profile")}
      </nav>
      <div class="nav-user tag">${user ? esc(user.name) : ""}${user && user.role === "admin" ? ' <span class="badge admin">Admin</span>' : ""}</div>
    </div>`;
  if (user) {
    api("/messages/unread").then((r) => {
      const c = document.getElementById("msg-count");
      if (c && r.unread > 0) { c.textContent = r.unread; c.hidden = false; }
    }).catch(() => {});
  }
}
