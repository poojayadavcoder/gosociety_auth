import jwt from "jsonwebtoken";
import Admin from "../models/Admin.js";
import User from "../models/User.js";
import Staff from "../models/Staff.js";
import redisClient from "../config/redis.js";

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET
    );

    console.log(`[AUTH] Token verified for: ${decoded.id} (${decoded.type})`);

    // Check Redis for cached user session with a timeout to prevent hanging on Vercel
    let cachedUser = null;
    try {
        const redisPromise = redisClient.get(`user:${decoded.id}`);
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Redis timeout')), 2000));
        cachedUser = await Promise.race([redisPromise, timeoutPromise]);
    } catch (redisErr) {
        console.warn(`[AUTH] Redis unavailable or timed out: ${redisErr.message}. Falling back to DB.`);
    }

    let user;
    if (cachedUser) {
        console.log(`[Redis] AUTH Cache HIT for user: ${decoded.id}`);
        user = JSON.parse(cachedUser);
    } else {
        console.log(`[Redis] AUTH Cache MISS for user: ${decoded.id} (using DB)`);
        if (decoded.type === "admin") {
          user = await Admin.findById(decoded.id);
        } else if (decoded.type === "user") {
          user = await User.findById(decoded.id);
        } else if (decoded.type === "staff") {
          user = await Staff.findById(decoded.id);
        }
    }

    if (!user) {
      console.error(`[AUTH] User record not found in DB/Cache for ID: ${decoded.id}`);
      return res.status(401).json({ message: "User not found (or invalid session)" });
    }

    req.user = user;
    req.userType = decoded.type;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
        const expiredAt = new Date(err.expiredAt).toISOString();
        console.error(`[AUTH] Token EXPIRED at ${expiredAt} for token: ${token.substring(0, 20)}...`);
        return res.status(401).json({ message: "Token expired", expiredAt });
    }
    console.error(`[AUTH] JWT Verification FAILED: ${err.message}`);
    res.status(401).json({ message: "Invalid token" });
  }
};

export default authMiddleware;
