const mongoose = require("mongoose");

async function dbConnect() {
  mongoose
    .connect("mongodb://127.0.0.1:27017/app")
    .then(() => console.log("Connected Successfully"))
    .catch((error) => console.log("Failed to connect", error));
}

module.exports = {dbConnect}