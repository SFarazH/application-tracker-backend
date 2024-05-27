const mongoose = require("mongoose");

const applicationSchema = mongoose.Schema({
  userId: String,
  companyName: String,
  jobRole: String,
  platform : String,
  dateApplied : Date,
  status : String
});

module.exports = mongoose.model("Application", applicationSchema);