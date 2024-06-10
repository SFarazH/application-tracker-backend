const express = require("express");
const router = express.Router();
const {
  addApplication,
  deleteApplication,
  updateStatus,
  getApplication,
} = require("../controller/application");
const { authenticate } = require("../middleware/authenticate");

router.post("/add", authenticate, addApplication);
router.delete("/rem", authenticate, deleteApplication);
router.patch("/update", authenticate, updateStatus);
router.get("/get", authenticate, getApplication);
module.exports = router;
