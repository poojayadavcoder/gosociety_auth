import Admin from "../models/Admin.js";
import User from "../models/User.js";
import Staff from "../models/Staff.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { generateAccessToken, generateRefreshToken } from "../config/jwt.js";
import redisClient from "../config/redis.js";


export const register = async (req, res) => {
  try {
    const { email, mobile, displayName, password, roleId, isSuperadmin } = req.body;

    if (!email || !mobile || !displayName || !password || !roleId) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if email or mobile already exists
    const existingAdmin = await Admin.findOne({
      $or: [{ email }, { mobile }]
    });

    if (existingAdmin) {
      return res.status(409).json({ message: "Admin with this email or mobile already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newAdmin = new Admin({
      email,
      mobile,
      displayName,
      password: hashedPassword,
      roleId,
      isSuperadmin: isSuperadmin || false
    });

    await newAdmin.save();

    res.status(201).json({ message: "Admin registered successfully", adminId: newAdmin._id });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /auth/login
 * Admin only login.
 */
export const login = async (req, res) => {
  try {
    let { identifier, password, mobile, email } = req.body;

    // If identifier is not provided, check if mobile or email is provided
    if (!identifier) {
      if (mobile) {
        identifier = mobile;
      } else if (email) {
        identifier = email;
      }
    }

    if (!identifier || !password) {
      return res.status(400).json({ message: "Missing credentials" });
    }

    // Check if identifier is email or mobile
    const query = identifier.includes("@")
      ? { email: identifier }
      : { mobile: identifier };

    // Find admin by email OR mobile
    const admin = await Admin.findOne(query);

    if (!admin) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const accessToken = generateAccessToken(admin, "admin");
    const refreshToken = generateRefreshToken(admin, "admin");

    // Save refresh token
    admin.refreshToken = refreshToken;
    await admin.save();

    // Cache user session in Redis (TTL: 1 hour)
    const sessionData = {
      id: admin._id,
      email: admin.email,
      displayName: admin.displayName,
      mobile: admin.mobile,
      roleId: admin.roleId,
      isSuperadmin: admin.isSuperadmin,
      type: "admin"
    };
    await redisClient.set(`user:${admin._id}`, JSON.stringify(sessionData), "EX", 3600);

    res.json({
      accessToken,
      refreshToken,
      user: { // Keeping 'user' key for frontend compatibility if needed, else could be 'admin'
        id: admin._id,
        email: admin.email,
        displayName: admin.displayName,
        mobile: admin.mobile,
        roleId: admin.roleId,
        isSuperadmin: admin.isSuperadmin,
        type: "admin"
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /auth/refresh
 */
export const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const admin = await Admin.findById(decoded.id);

    if (!admin || admin.refreshToken !== refreshToken) {
       return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = generateAccessToken(admin, "admin");

    res.json({ accessToken: newAccessToken });

  } catch (err) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
};

/**
 * POST /auth/logout
 */
export const logout = async (req, res) => {
  try {
    if (req.user) {
      const userId = req.user.id || req.user._id;
      const userType = req.userType; // Set by authMiddleware

      console.log(`[Logout] User: ${userId} | type: ${userType}`);

      let Model;
      if (userType === "admin") Model = Admin;
      else if (userType === "staff") Model = Staff;
      else Model = User;

      await Model.findByIdAndUpdate(userId, { 
        refreshToken: null,
        notificationToken: null 
      });

      // Remove session from Redis
      await redisClient.del(`user:${userId}`);
    }
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: error.message });
  }
};
