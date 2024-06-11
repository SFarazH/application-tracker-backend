const express = require("express");
const router = express.Router();
const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const { authenticate } = require("../middleware/authenticate");
const {
  addResume,
  displayResume,
  getResume,
  deleteResume,
} = require("../controller/resume");

router.post("/add", upload.single("file"), authenticate, addResume);
router.get("/get", authenticate, displayResume);
router.get("/getId", authenticate, getResume);
router.delete("/del", authenticate, deleteResume);
module.exports = router;
