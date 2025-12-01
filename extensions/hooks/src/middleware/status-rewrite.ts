import type { Request, Response, NextFunction } from "express";
import { createError } from "@directus/errors";

const NotFoundError = createError("ROUTE_NOT_FOUND", "Not found.", 404);

export function createStatusRewriteMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    const originalSend = res.send.bind(res);

    res.send = function (body?: any) {
      if (res.statusCode === 403) {
        res.statusCode = 404;
        const error = new NotFoundError();
        return originalSend({
          errors: [
            {
              message: error.message,
              extensions: {
                code: "ROUTE_NOT_FOUND",
                path: req.originalUrl,
              },
            },
          ],
        });
      }
      return originalSend(body);
    };

    next();
  };
}
