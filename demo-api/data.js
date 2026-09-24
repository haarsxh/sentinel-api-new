// Seed data for the sandboxed demo target.
// This is a deliberately vulnerable practice app (think DVWA / OWASP Juice Shop),
// used ONLY as the scanner's local test target. Do not deploy it.

export const users = [
  {
    id: 1,
    username: "alice",
    password: "alice-password",        // stored in clear on purpose (seeded flaw)
    email: "alice@example.com",
    ssn: "111-11-1111",                // sensitive field that should never leave the server
    role: "user",
    apiToken: "tok_alice_9f3a",
  },
  {
    id: 2,
    username: "bob",
    password: "bob-password",
    email: "bob@example.com",
    ssn: "222-22-2222",
    role: "user",
    apiToken: "tok_bob_1c7d",
  },
  {
    id: 3,
    username: "admin",
    password: "admin-password",
    email: "admin@example.com",
    ssn: "333-33-3333",
    role: "admin",
    apiToken: "tok_admin_root",
  },
];

export const orders = [
  { id: 1001, ownerId: 1, item: "Wireless mouse", total: 24.99, card: "4111-1111-1111-1111" },
  { id: 1002, ownerId: 1, item: "Mechanical keyboard", total: 79.0, card: "4111-1111-1111-1111" },
  { id: 2001, ownerId: 2, item: "Standing desk", total: 320.0, card: "5500-0000-0000-0004" },
  { id: 3001, ownerId: 3, item: "Server rack", total: 1200.0, card: "3400-0000-0000-009" },
];

export const documents = [
  { id: "doc-a1", ownerId: 1, title: "Alice tax return 2025", body: "confidential" },
  { id: "doc-b1", ownerId: 2, title: "Bob medical notes", body: "confidential" },
];
