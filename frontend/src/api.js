const BASE = "/api";

export async function startScan(baseUrl, authCookies = null, authHeadersJson = null) {
  const res = await fetch(`${BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      base_url: baseUrl,
      auth_cookies: authCookies || null,
      auth_headers_json: authHeadersJson || null,
    }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getScans() {
  const res = await fetch(`${BASE}/scans`);
  return res.json();
}

export async function getScan(id) {
  const res = await fetch(`${BASE}/scan/${id}`);
  return res.json();
}

export async function getScanEndpoints(id) {
  const res = await fetch(`${BASE}/scan/${id}/endpoints`);
  return res.json();
}

export async function getScanFindings(id) {
  const res = await fetch(`${BASE}/scan/${id}/findings`);
  return res.json();
}
