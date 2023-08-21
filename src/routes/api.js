import { Router } from "express";
import authController from "../controllers/auth";
import linkController from "../controllers/link";
import isAuthenticated from "../middleware/isAuthenticated";
import {
  loginValidator,
  registorValidator,
} from "../middleware/validator/auth";
import { validate } from "../middleware/validator";
import { createLinkValidator } from "../middleware/validator/link";

const apiRoutes = Router();

apiRoutes.post(
  "/register",
  registorValidator,
  validate,
  authController.register
);

apiRoutes.post("/login", loginValidator, validate, authController.login);
apiRoutes.post("/logout", isAuthenticated, authController.logout);

apiRoutes.post(
  "/link",
  isAuthenticated,
  createLinkValidator,
  validate,
  linkController.create
);
apiRoutes.put(
  "/link",
  isAuthenticated,
  createLinkValidator,
  validate,
  linkController.update
);
apiRoutes.get("/link/:userId", linkController.listAllbyUserId);
apiRoutes.delete("/link", isAuthenticated, linkController.deleteLink);

apiRoutes.get("/protected", isAuthenticated, function (req, res) {
  res.status(200).json({ message: "Protected Route", user: req.user });
});
export default apiRoutes;
