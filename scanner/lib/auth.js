// Establish an authenticated session per configured identity.
// Sessions carry the auth header the checks attach to requests.

import { request } from "./http.js";

export async function establishSessions(config) {
  const sessions = [];
  const auth = config.auth || {};
  const header = auth.header || "Authorization";
  const scheme = auth.scheme ?? "Bearer";

  for (const identity of config.identities || []) {
    let authHeader = null;

    if (identity.token) {
      // Pre-supplied token.
      authHeader = scheme ? `${scheme} ${identity.token}` : identity.token;
    } else if (auth.loginPath && identity.credentials) {
      const res = await request(config.baseUrl, {
        method: "POST",
        path: auth.loginPath,
        body: identity.credentials,
      });
      const token = res.json?.[auth.tokenField || "token"];
      if (!token) {
        throw new Error(`Login failed for identity "${identity.label}" (status ${res.status})`);
      }
      authHeader = scheme ? `${scheme} ${token}` : token;
    }

    sessions.push({
      label: identity.label,
      level: identity.level ?? 10,
      headers: authHeader ? { [header]: authHeader } : {},
      authHeader,
    });
  }
  return sessions;
}
