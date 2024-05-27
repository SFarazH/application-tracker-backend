const express = require("express");
const router = express.Router();
const { addNote, deleteNote } = require("../controller/notes");
const { authenticate } = require("../middleware/authenticate");

router.post("/add", authenticate, addNote);
router.delete("/remove", authenticate, deleteNote);

module.exports = router;
