// Thin HTTP client around global fetch with timing + safe error capture.
// Records every request so the scanner can build reproducible proof-of-concepts.

export async function request(baseUrl, { method = "GET", path, headers = {}, body, timeoutMs = 8000 } = {}) {
  const url = baseUrl.replace(/\/$/, "") + path;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = performance.now();

  try {
    const res = await fetch(url, {
      method,
      headers: {
        ...(body ? { "content-type": "application/json" } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }

    return {
      ok: res.ok,
      status: res.status,
      json,
      text,
      ms: Math.round(performance.now() - start),
      request: { url, method, headers, body },
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: err.name === "AbortError" ? "timeout" : String(err),
      ms: Math.round(performance.now() - start),
      request: { url, method, headers, body },
    };
  } finally {
    clearTimeout(timer);
  }
}
