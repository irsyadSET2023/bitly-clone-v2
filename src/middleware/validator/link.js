import { body } from "express-validator";

export const createLinkValidator = [
  body("link")
    .exists()
    .withMessage("link is required")
    .isURL()
    .withMessage("link is invalid"),
];
