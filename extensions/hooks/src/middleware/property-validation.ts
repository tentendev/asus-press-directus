/**
 * Property validation middleware for request body validation
 * Ensures only allowed properties are present in the request body
 */

/**
 * Creates middleware to validate GraphQL request properties
 * Only allows: query, variables, operationName
 */
export const createGraphQLPropertyValidation = () => {
  return (req: any, res: any, next: any) => {
    const allowedProps = ["query", "variables", "operationName"];
    const props = Object.keys(req.body || {});
    const isAllowed = props.every((prop) => allowedProps.includes(prop));

    if (!isAllowed) {
      return res
        .status(400)
        .send({ error: "Request contains invalid properties." });
    }

    next();
  };
};

/**
 * Creates middleware to validate /auth/login request properties
 * Only allows: email, password, mode
 */
export const createAuthLoginPropertyValidation = () => {
  return (req: any, res: any, next: any) => {
    const allowedProps = ["email", "password", "mode"];
    const props = Object.keys(req.body || {});
    const isAllowed = props.every((prop) => allowedProps.includes(prop));

    if (!isAllowed) {
      return res
        .status(400)
        .send({ error: "Request contains invalid properties." });
    }

    next();
  };
};
