import { validationResult } from "express-validator";

export function validate(req, res, next) {
  const err = validationResult(req);
  if (!err.isEmpty()) {
    res.status(403).json({ err });
  } else {
    next();
  }
}
