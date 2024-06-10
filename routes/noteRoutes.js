const express = require("express");
const router = express.Router();
const { addNote, deleteNote, getNotes } = require("../controller/notes");
const { authenticate } = require("../middleware/authenticate");

router.post("/add", authenticate, addNote);
router.delete("/delete", authenticate, deleteNote);
router.get("/get", authenticate, getNotes);

module.exports = router;
