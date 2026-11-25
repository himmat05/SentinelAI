/**
 * SentinelAI - Frontend Security & UX Helpers
 * ============================================
 * 1. Strict HTML entity escaping (prevents Stored XSS when rendering untrusted HTTP paths/reasons)
 * 2. Operator authentication token header helper
 * 3. Non-blocking dark cyber SOC toast notifications
 */

const TOKEN_STORAGE_KEY = "sentinel_operator_token";

/**
 * Escape untrusted text before inserting into HTML template strings.
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/\//g, "&#x2F;");
}

export function getOperatorToken() {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

export function setOperatorToken(token) {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
    } else {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage error in restricted context
  }
}

/**
 * Attach X-Sentinel-Token header if operator token is configured in UI.
 */
export function getOperatorHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  const token = getOperatorToken();
  if (token) {
    headers["X-Sentinel-Token"] = token;
  }
  return headers;
}

/**
 * Display a non-blocking SOC toast alert in the bottom-right corner.
 */
export function showToast(title, message = "", type = "info", durationMs = 4500) {
  let container = document.getElementById("sentinel-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "sentinel-toast-container";
    container.style.cssText = [
      "position: fixed",
      "bottom: 1.25rem",
      "right: 1.25rem",
      "z-index: 9999",
      "display: flex",
      "flex-direction: column",
      "gap: 0.65rem",
      "max-width: 390px",
      "pointer-events: none"
    ].join(";");
    document.body.appendChild(container);
  }

  const palette = {
    success: { border: "#10b981", bg: "rgba(6, 78, 59, 0.94)", icon: "✅" },
    error: { border: "#ef4444", bg: "rgba(127, 29, 29, 0.94)", icon: "🚨" },
    warning: { border: "#f59e0b", bg: "rgba(120, 53, 15, 0.94)", icon: "⚠️" },
    info: { border: "#38bdf8", bg: "rgba(15, 23, 42, 0.95)", icon: "🛡️" }
  };
  const style = palette[type] || palette.info;

  const toast = document.createElement("div");
  toast.style.cssText = [
    `background: ${style.bg}`,
    `border: 1px solid ${style.border}`,
    "border-radius: 10px",
    "padding: 0.85rem 1rem",
    "color: #f8fafc",
    "box-shadow: 0 10px 25px rgba(0, 0, 0, 0.45)",
    "backdrop-filter: blur(8px)",
    "pointer-events: auto",
    "font-size: 0.82rem",
    "line-height: 1.45"
  ].join(";");

  const headerRow = document.createElement("div");
  headerRow.style.cssText = "display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; font-weight: 700; margin-bottom: 0.2rem;";
  const titleSpan = document.createElement("span");
  titleSpan.textContent = `${style.icon} ${title}`;
  const closeBtn = document.createElement("button");
  closeBtn.textContent = "×";
  closeBtn.style.cssText = "background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 1.1rem; line-height: 1;";
  closeBtn.onclick = () => toast.remove();

  headerRow.appendChild(titleSpan);
  headerRow.appendChild(closeBtn);
  toast.appendChild(headerRow);

  if (message) {
    const bodyEl = document.createElement("div");
    bodyEl.style.cssText = "color: #cbd5e1; white-space: pre-line; word-break: break-word;";
    bodyEl.textContent = message;
    toast.appendChild(bodyEl);
  }

  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.remove();
  }, durationMs);
}
