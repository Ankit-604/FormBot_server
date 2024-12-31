const jwt = require("jsonwebtoken");

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No valid access token" });
  }

  if (!process.env.ACCESS_TOKEN_SECRET) {
    console.error("ACCESS_TOKEN_SECRET is not defined in the environment variables.");
    return res.status(500).json({ message: "Server configuration error." });
  }

  try {
    const decodedAccess = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    req.user = decodedAccess;
    return next();
  } catch (error) {
    console.error("Access token verification failed:", error.message);

    return res.status(403).json({ message: "Forbidden: Invalid or expired token" });
  }
};

module.exports = authenticateToken;
