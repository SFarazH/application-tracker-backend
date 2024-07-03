const userModel = require("../models/userModel");
const tokenSchema = require("../models/tokenModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Enter all the details!" });
  }

  try {
    const verifyEmail = await userModel.findOne({ email: email });
    if (verifyEmail) {
      return res.status(403).json({ message: "Email already registered!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new userModel({
      name: name,
      email: email,
      password: hashedPassword,
    });

    await user.save();
    return res.status(201).json({
      message: "User registered successfully!",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Please enter email and password!" });
  }

  try {
    const user = await userModel.findOne({ email: email });
    if (!user) {
      return res.status(401).json({ message: "Email not registered" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect Password" });
    }

    const jwtToken = jwt.sign(
      {
        id: user._id,
        email: user.email,
      },
      process.env.SECRET_KEY,
      {
        expiresIn: "1d",
      }
    );

    res.cookie("accessToken", jwtToken, {
      httpOnly: true,
      sameSite: "none",
      secure: process.env.NODE_ENV === "production", // Set to true if using HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.status(200).json({
      message: "logged in",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
const logout = async (req, res) => {
  try {
    res.cookie("accessToken", "", {
      httpOnly: true,
      sameSite: "strict",
      maxAge: 0,
    });

    return res.status(200).json({
      message: "logged out",
    });
  } catch (error) {
    return res.status(500).json({
      message: error,
    });
  }
};
const verify = async (req, res) => {
  const user = req.user;
  const userData = {
    name: user.name,
    email: user.email,
  };
  res.status(200).json(userData);
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ message: "User with this email does not exist." });
    }

    const token = crypto.randomBytes(20).toString("hex");

    const newToken = new tokenSchema({
      userId: user._id,
      token: token,
    });

    await newToken.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.USER_ID,
        pass: process.env.PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
        secureProtocol: "TLSv1_method",
        ciphers: "SSLv3",
        minVersion: "TLSv1",
      },
    });

    const mailOptions = {
      to: user.email,
      from: process.env.USER_ID,
      subject: "Password Reset - Application Tracker",
      text: `
      Please click on the following link, or paste this into your browser to complete the process:\n\n
      http://${req.headers.host}/reset/${token}\n\n
      If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };
    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Mail has been sent" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const handleResetPassword = async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;
    const token = await tokenSchema.findOne({ token: req.params.token });
    if (!token) {
      return res
        .status(400)
        .send("Password reset token is invalid or has expired.");
    }

    const user = await userModel.findById(token.userId);
    if (!user) {
      return res.status(400).send("User not found.");
    }

    if (password === confirmPassword) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      await user.save();
      await tokenSchema.deleteOne({ token: req.params.token });

      res.send("Password has been reset successfully.");
    } else {
      res.status(400).send("Passwords do not match.");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error on the server.");
  }
};

module.exports = {
  login,
  register,
  verify,
  logout,
  forgotPassword,
  handleResetPassword,
};
