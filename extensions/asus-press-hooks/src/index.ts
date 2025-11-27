import { defineHook } from "@directus/extensions-sdk";
import type { Application } from "express";
import { createCheckOriginMiddleware } from "./middleware/check-origin.js";
import {
  createGraphQLPropertyValidation,
  createAuthLoginPropertyValidation,
} from "./middleware/property-validation.js";
import { createGraphQLEndpointValidation } from "./middleware/endpoint-validation.js";

export default defineHook(({ init }) => {
  init("routes.before", ({ app }: Record<"app", Application>) => {
    // Read allowed origins from environment at runtime
    const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
      : [];

    // Get the request URL for CSRF checks
    const REQUEST_URL = process.env.PUBLIC_URL || "http://localhost:8055";

    // Security middleware (origin validation + CSRF protection)
    app.use(createCheckOriginMiddleware(ALLOWED_ORIGINS, REQUEST_URL));

    // Property validation middleware
    app.use("/graphql", createGraphQLPropertyValidation());
    app.use("/auth/login", createAuthLoginPropertyValidation());

    // Endpoint validation middleware
    app.use(createGraphQLEndpointValidation());

    console.log(
      "--- [init:routes.before] ASUS Press Custom Middleware ---"
    );
  });
});
