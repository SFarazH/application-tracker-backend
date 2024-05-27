const mongoose = require("mongoose");

const resumeSchema = new mongoose.Schema({
  name: String,
  data: Buffer,
  contentType: String,
  userId: String,
});

const Resume = mongoose.model("Resume", resumeSchema);

module.exports = Resume;