const mongoose = require("mongoose");
const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
    },
    email: {
      type: String,
    },
    password: {
      type: String,
    },
    notes: [],
    role: {
      type: String,
      default: "normal",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
