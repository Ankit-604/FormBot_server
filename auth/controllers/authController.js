const jwt = require("jsonwebtoken");
const User = require("../../models/userModel");
const dotenv = require("dotenv");
dotenv.config();

const jwtExpiresIn = "150m";

const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: jwtExpiresIn,
  });
};

const registerUser = async (req, res) => {
  const { username, email, password } = req.body;
  console.log(username, email, password);
  try {
    const existingUserName = await User.exists({ username });

    if (existingUserName) {
      return res.status(400).json({ message: "Username already exists" });
    }
    const existingEmail = await User.exists({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const user = new User({ username, email, password });

    await user.save();

    res.status(200).json({ message: "Success" });
  } catch (error) {
    console.error("Error registering user:", error.message);
    res.status(400).json({ message: "Error", error: error.message });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email" });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const accessToken = generateAccessToken(user._id);

    const userData = user.toObject();

    delete userData.password;

    res.status(200).json({
      message: "Success",
      user: userData,
      accessToken,
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Server error during login" });
  }
};

module.exports = {
  registerUser,
  loginUser,
};
