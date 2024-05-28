const jwt = require("jsonwebtoken");
const userSchema = require("../models/userModel");

const authenticate = async (req, res, next) => {
  // const token = req.headers.authorization?.split(" ")[1];
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    const user = await userSchema.findById(decodedToken.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Error during token verification:", error); // Log the error
    res.status(401).json({ message: "Invalid token" });
  }
};

module.exports = { authenticate };
