const express = require("express");

const router = express.Router();

const {
  login,
  register,
  verify,
  logout,
  forgotPassword,
  handleResetPassword,
} = require("../controller/auth");
const { authenticate } = require("../middleware/authenticate");

router.post("/login", login);
router.post("/register", register);
router.get("/verify", authenticate, verify);
router.post("/logout", authenticate, logout);
router.post("/forgot-password", forgotPassword);
router.post("/reset/:token", handleResetPassword);

module.exports = router;
