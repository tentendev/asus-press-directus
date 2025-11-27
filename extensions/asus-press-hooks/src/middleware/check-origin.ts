/**
 * Security middleware for origin validation and CSRF protection
 * Following Astro's approach while maintaining backward compatibility
 */

/**
 * Content types that can be passed when sending a request via a form
 * @see https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement/enctype
 */
export const FORM_CONTENT_TYPES = [
  "application/x-www-form-urlencoded",
  "multipart/form-data",
  "text/plain",
];

/**
 * HTTP methods that are considered safe and don't require CSRF checks
 * @see https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP
 */
export const SAFE_METHODS = ["GET", "HEAD", "OPTIONS"];

/**
 * Check if the content-type header indicates a form-like submission
 */
export const hasFormLikeHeader = (contentType: string | null): boolean => {
  if (contentType) {
    for (const formContentType of FORM_CONTENT_TYPES) {
      if (contentType.toLowerCase().includes(formContentType)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Unified security middleware combining origin validation and CSRF protection
 * Follows Astro's approach while maintaining backward compatibility
 *
 * @param allowedOrigins - List of allowed origins (hostnames will be extracted)
 * @param requestUrl - The URL of the current request (for same-origin checks)
 * @returns Express middleware function
 */
export const createCheckOriginMiddleware = (
  allowedOrigins: string[],
  requestUrl: string
) => {
  return (req: any, res: any, next: any) => {
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const method = req.method;

    console.log(`[Request] ${method} ${req.originalUrl}`);

    // Skip checks for safe methods (GET, HEAD, OPTIONS)
    if (SAFE_METHODS.includes(method)) {
      return next();
    }

    // If ALLOWED_ORIGINS is configured, use allowlist validation
    if (allowedOrigins.length > 0) {
      // If neither origin nor referer is present, allow (direct API calls, server-to-server)
      if (!origin && !referer) {
        return next();
      }

      // Extract hostname from origin or referer
      const sourceUrl = origin || referer;
      if (!sourceUrl) {
        return next();
      }

      try {
        const parsedUrl = new URL(sourceUrl);
        const sourceHost = parsedUrl.hostname;

        // Check if the source hostname matches any allowed origin
        const isAllowed = allowedOrigins.some((allowedOrigin) => {
          try {
            const allowedUrl = new URL(allowedOrigin);
            return sourceHost === allowedUrl.hostname;
          } catch {
            // If allowed origin is just a hostname (without protocol), compare directly
            return sourceHost === allowedOrigin;
          }
        });

        if (!isAllowed) {
          console.warn(
            `[Security] Blocked request from unauthorized origin/referer: ${sourceUrl}`
          );
          return res
            .status(403)
            .send({ error: "Access denied: unauthorized origin." });
        }
      } catch {
        // Invalid URL format, reject
        console.warn(`[Security] Blocked request with invalid URL format`);
        return res
          .status(403)
          .send({ error: "Access denied: unauthorized origin." });
      }
    } else {
      // If no ALLOWED_ORIGINS configured, use CSRF protection (Astro-style)
      // If no origin header, allow (server-to-server)
      if (!origin) {
        return next();
      }

      const isSameOrigin = origin === requestUrl;
      const contentType = req.headers["content-type"];

      // Check for form-like submissions
      if (contentType) {
        const isFormLike = hasFormLikeHeader(contentType);
        if (isFormLike && !isSameOrigin) {
          console.warn(
            `[CSRF] Blocked cross-site ${method} form submission from: ${origin}`
          );
          return res.status(403).send({
            error: `Cross-site ${method} form submissions are forbidden`,
          });
        }
      } else {
        // No content-type header, check if cross-origin
        if (!isSameOrigin) {
          console.warn(
            `[CSRF] Blocked cross-site ${method} request without content-type from: ${origin}`
          );
          return res.status(403).send({
            error: `Cross-site ${method} form submissions are forbidden`,
          });
        }
      }
    }

    return next();
  };
};
