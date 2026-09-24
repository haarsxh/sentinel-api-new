// Authorization / scope guard.
//
// The problem statement makes this the critical constraint: the scanner must only
// run against explicitly authorized, sandboxed targets. This module refuses to run
// otherwise. It is intentionally strict and fails closed.

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

export function assertAuthorized(config) {
  let url;
  try {
    url = new URL(config.baseUrl);
  } catch {
    throw new Error(`Invalid baseUrl: ${config.baseUrl}`);
  }

  const isLoopback = LOOPBACK.has(url.hostname);

  if (isLoopback) return { host: url.hostname, mode: "loopback" };

  // Non-local target: require an explicit typed acknowledgment in the config.
  const expected = "I am authorized to test this target";
  if (config.authorization !== expected) {
    throw new Error(
      [
        `Refusing to scan non-local target "${url.hostname}".`,
        `SentinelAPI only runs against sandboxed / authorized APIs.`,
        `If you own or have written permission to test this target, add this to the config:`,
        `  "authorization": "${expected}"`,
      ].join("\n")
    );
  }
  return { host: url.hostname, mode: "authorized-remote" };
}
