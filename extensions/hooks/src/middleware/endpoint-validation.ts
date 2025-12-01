/**
 * Endpoint validation middleware
 * Blocks access to invalid or unauthorized endpoints
 */

/**
 * Creates middleware to block invalid GraphQL endpoints
 * Blocks all /graphql/* endpoints except /graphql/system
 */
export const createGraphQLEndpointValidation = () => {
  return (req: any, res: any, next: any) => {
    // Block all /graphql/* endpoints except /graphql/system
    if (/^\/graphql\/(?!system(?:\/|$)).*/.test(req.originalUrl)) {
      return res.status(400).send({ error: "Invalid endpoint." });
    }
    next();
  };
};
