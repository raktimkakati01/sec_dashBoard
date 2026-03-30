const BASE = "/api";
const AUTH_TOKEN_KEY = "sec_dashboard_admin_token";

async function readJsonOrThrow(res) {
  const contentType = res.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const message = typeof payload === "string" ? payload : payload?.detail || `Request failed with ${res.status}`;
    const error = new Error(message);
    error.status = res.status;
    throw error;
  }
  return payload;
}

function getAuthHeaders(includeAuth = true) {
  const headers = {};
  if (includeAuth) {
    const token = getStoredToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  return headers;
}

async function apiRequest(path, options = {}) {
  const { includeAuth = true, headers = {}, body, ...rest } = options;
  const isJson = body && !(body instanceof FormData);
  const res = await fetch(`${BASE}${path}`, {
    ...rest,
    headers: {
      ...getAuthHeaders(includeAuth),
      ...(isJson ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: isJson ? JSON.stringify(body) : body,
  });
  return readJsonOrThrow(res);
}

export function getStoredToken() {
  return window.localStorage.getItem(AUTH_TOKEN_KEY);
}

export function clearStoredToken() {
  window.localStorage.removeItem(AUTH_TOKEN_KEY);
}

function setStoredToken(token) {
  window.localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export async function loginAdmin(email, password) {
  const data = await apiRequest("/auth/login", {
    method: "POST",
    includeAuth: false,
    body: { email, password },
  });
  setStoredToken(data.token);
  return data;
}

export async function logoutAdmin() {
  try {
    await apiRequest("/auth/logout", { method: "POST" });
  } finally {
    clearStoredToken();
  }
}

export function getCurrentAdmin() {
  return apiRequest("/auth/me");
}

export function requestPasswordReset(email) {
  return apiRequest("/auth/forgot-password", {
    method: "POST",
    includeAuth: false,
    body: { email },
  });
}

export function resetPassword(email, code, newPassword) {
  return apiRequest("/auth/reset-password", {
    method: "POST",
    includeAuth: false,
    body: { email, code, new_password: newPassword },
  });
}

export async function startScan(
  baseUrl,
  authCookies = null,
  authHeadersJson = null,
  enableNuclei = false,
  nucleiTags = null,
) {
  return apiRequest("/scan", {
    method: "POST",
    body: {
      base_url: baseUrl,
      auth_cookies: authCookies || null,
      auth_headers_json: authHeadersJson || null,
      enable_nuclei: enableNuclei,
      nuclei_tags: nucleiTags || null,
    },
  });
}

export async function getScans() {
  return apiRequest("/scans");
}

export async function getScan(id) {
  return apiRequest(`/scan/${id}`);
}

export async function getScanEndpoints(id) {
  return apiRequest(`/scan/${id}/endpoints`);
}

export async function getScanFindings(id) {
  return apiRequest(`/scan/${id}/findings`);
}
