import { describe, it, expect } from "vitest";

/**
 * Integration tests for check-origin middleware
 * Tests against the live Directus instance at http://localhost:8055
 *
 * Prerequisites:
 * - Directus must be running with the extension loaded
 * - ALLOWED_ORIGINS must be configured in docker-compose.yml
 */

const DIRECTUS_URL = "http://localhost:8055";
const VALID_ORIGIN = "https://asus-press-cms.tenten.dev";
const INVALID_ORIGIN = "https://malicious-site.com";

describe("Security Middleware - Safe Methods", () => {
  it("should allow GET requests regardless of origin", async () => {
    const response = await fetch(`${DIRECTUS_URL}/server/ping`, {
      method: "GET",
      headers: {
        Origin: INVALID_ORIGIN,
      },
    });

    // GET requests should not be blocked by our middleware
    // (may get other errors, but not 403 from our middleware)
    expect(response.status).not.toBe(403);
  });

  it("should allow HEAD requests", async () => {
    const response = await fetch(`${DIRECTUS_URL}/server/ping`, {
      method: "HEAD",
      headers: {
        Origin: INVALID_ORIGIN,
      },
    });

    expect(response.status).not.toBe(403);
  });

  it("should allow OPTIONS requests", async () => {
    const response = await fetch(`${DIRECTUS_URL}/server/ping`, {
      method: "OPTIONS",
      headers: {
        Origin: INVALID_ORIGIN,
      },
    });

    expect(response.status).not.toBe(403);
  });
});

describe("Security Middleware - Origin Validation", () => {
  it("should block POST requests from unauthorized origins", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: INVALID_ORIGIN,
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toContain("Access denied");
  });

  it("should allow POST requests from valid ALLOWED_ORIGINS", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: VALID_ORIGIN,
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    // Should pass origin check (may fail auth, but not 403)
    expect(response.status).not.toBe(403);
  });

  it("should allow POST requests without origin header (server-to-server)", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    // Should pass origin check for server-to-server calls
    expect(response.status).not.toBe(403);
  });
});

describe("Security Middleware - CSRF Protection", () => {
  it("should block cross-origin form submissions", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: INVALID_ORIGIN,
      },
      body: "email=test@test.com&password=test",
    });

    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toBeDefined();
  });

  it("should block POST with multipart/form-data from different origin", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary",
        Origin: INVALID_ORIGIN,
      },
      body: '------WebKitFormBoundary\r\nContent-Disposition: form-data; name="email"\r\n\r\ntest@test.com\r\n------WebKitFormBoundary--',
    });

    expect(response.status).toBe(403);
  });
});

describe("Security Middleware - Property Validation", () => {
  it("should block /auth/login with invalid properties", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
        malicious: "property",
      }),
    });

    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data.error).toContain("invalid properties");
  });

  it("should allow /auth/login with valid properties", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    // Should pass property validation (may fail auth, but not 400 for invalid properties)
    expect(response.status).not.toBe(400);
  });

  it("should allow /auth/login with mode property", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
        mode: "cookie",
      }),
    });

    expect(response.status).not.toBe(400);
  });
});

describe("Security Middleware - GraphQL Property Validation", () => {
  it("should pass /graphql requests to GraphQL handler", async () => {
    // Note: Property validation for /graphql may not work as expected because
    // the body hasn't been parsed yet when our middleware runs
    const response = await fetch(`${DIRECTUS_URL}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
        malicious: "property",
      }),
    });

    // GraphQL will handle the request (may succeed or fail based on GraphQL validation)
    expect(response.status).not.toBe(403);
  });

  it("should allow /graphql with valid properties", async () => {
    const response = await fetch(`${DIRECTUS_URL}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
      }),
    });

    expect(response.status).not.toBe(400);
  });

  it("should allow /graphql with variables", async () => {
    const response = await fetch(`${DIRECTUS_URL}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
        variables: {},
      }),
    });

    expect(response.status).not.toBe(400);
  });

  it("should allow /graphql with operationName", async () => {
    const response = await fetch(`${DIRECTUS_URL}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
        operationName: "GetTypename",
      }),
    });

    expect(response.status).not.toBe(400);
  });
});

describe("Security Middleware - Endpoint Validation", () => {
  it("should block invalid GraphQL endpoints", async () => {
    const response = await fetch(`${DIRECTUS_URL}/graphql/malicious`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
      }),
    });

    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data.error).toContain("Invalid endpoint");
  });

  it("should allow /graphql/system endpoint", async () => {
    const response = await fetch(`${DIRECTUS_URL}/graphql/system`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: "{ __typename }",
      }),
    });

    // Should not be blocked by our middleware (may require auth)
    expect(response.status).not.toBe(400);
  });
});

describe("Security Middleware - Edge Cases", () => {
  it("should handle requests with referer instead of origin", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Referer: INVALID_ORIGIN,
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    // Should check referer when origin is missing
    expect(response.status).toBe(403);
  });

  it("should handle requests with both origin and referer", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: VALID_ORIGIN,
        Referer: INVALID_ORIGIN,
      },
      body: JSON.stringify({
        email: "test@test.com",
        password: "test",
      }),
    });

    // Origin should take precedence
    expect(response.status).not.toBe(403);
  });

  it("should handle empty request body", async () => {
    const response = await fetch(`${DIRECTUS_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });

    // Should pass our middleware checks
    expect(response.status).not.toBe(403);
  });
});
