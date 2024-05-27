const userModel = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Enter all the details!" });
  }
  const verifyEmail = await userModel.findOne({ email: email });
  try {
    if (verifyEmail) {
      return res.status(403).json({
        message: "Email already registered!",
      });
    } else {
      bcrypt.hash(password, 10).then((hash) => {
        const user = new userModel({
          name: name,
          email: email,
          password: hash,
        });

        user
          .save()
          .then((response) => {
            return res.status(201).json({
              message: "User registered successfully!",
              success: true,
            });
          })
          .catch((error) => {
            res.status(500).json({
              error: error,
            });
          });
      });
    }
  } catch (error) {
    return res.status(412).send({
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
  let getUser;

  userModel
    .findOne({
      email: email,
    })
    .then((user) => {
      if (!user) {
        return res.status(401).json({
          message: "User does not exist",
        });
      }
      getUser = user;
      return bcrypt.compare(password, user.password);
    })
    .then((response) => {
      if (!response) {
        return res.status(401).json({
          message: "Incorrect Password",
        });
      } else {
        if (!process.env.SECRET_KEY) {
          return res.status(500).json({ error: "no key" });
        }
        let jwtToken = jwt.sign(
          {
            id: getUser._id,
            email: getUser.email,
          },
          process.env.SECRET_KEY,
          {
            expiresIn: "1d",
          }
        );
        return res.status(200).json({
          accessToken: jwtToken,
        });
      }
    })
    .catch((err) => {
      return res.status(401).json({
        messgae: err.message,
        success: false,
      });
    });
};

module.exports = { login, register };
