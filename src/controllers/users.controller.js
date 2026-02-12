import User from "../models/User.js";
import Society from "../models/Society.js";
import Admin from "../models/Admin.js";

import bcrypt from "bcryptjs";
import { generateAccessToken, generateRefreshToken } from "../config/jwt.js";
import { sendSMS } from "../utils/sms.js";
import redisClient from "../config/redis.js";



/**
 * POST /users
 * Register a new resident user.
 * Access: Public
 */
export const registerUser = async (req, res) => {
  try {
    const { societyId, email, mobile, displayName, password, profile, flat, tower, role } = req.body;

    // Validation
    if (!societyId || !mobile || !displayName) {
      return res.status(400).json({ message: "Missing required fields (societyId, mobile, displayName)" });
    }

    // Check if user already exists (by mobile or email) globally
    const existingUser = await User.findOne({
      $or: [
        { mobile },
        ...(email ? [{ email }] : [])
      ]
    });

    if (existingUser) {
      const isMobileMatch = existingUser.mobile === mobile;
      return res.status(409).json({ 
        message: isMobileMatch 
          ? "Mobile number already registered" 
          : "Email already registered" 
      });
    }


    let hashedPassword = undefined;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    // Merge flat and tower from body into profile if provided
    const userProfile = profile || {};
    if (flat) userProfile.flat = flat;
    if (tower) userProfile.tower = tower;

    // Map role (Owner -> resident, Tenant -> tenant)
    let userRole = ["resident"];
    if (role) {
      if (role.toLowerCase() === "owner") userRole = ["resident"];
      else if (role.toLowerCase() === "tenant") userRole = ["tenant"];
      else userRole = [role.toLowerCase()];
    }

    const newUser = new User({
      societyId,
      email,
      mobile,
      displayName,
      password: hashedPassword,
      role: userRole,
      profile: userProfile,
      status: "pending" // Residents are pending by default
    });

    await newUser.save();


    res.status(201).json({
      message: "Registration successful. Your account is pending approval.",
      userId: newUser._id
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /users/send-otp
 * Send OTP to user's mobile.
 * Access: Public
 */
export const sendOtp = async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({ message: "Mobile number is required" });
    }

    const user = await User.findOne({ mobile });

    if (!user) {
      return res.status(404).json({ message: "User not found with this mobile number" });
    }

    // Generate 4 digit OTP (for testing, we'll use 1234 or random)
    const otp = "1234";
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // In production, integrate with SMS gateway here
    console.log(`OTP for ${mobile}: ${otp}`);
    
    // Attempt to send real SMS
    await sendSMS(mobile, otp);


    res.json({ message: "OTP sent successfully", otp: process.env.NODE_ENV === 'development' ? otp : undefined });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /users/login
 * Resident user login.
 * Access: Public
 */
export const loginUser = async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({ message: "Missing mobile or otp" });
    }

    const user = await User.findOne({ mobile });

    if (!user) {
      return res.status(401).json({ message: "Invalid mobile or otp" });
    }

    if (user.status !== "active") {
      return res.status(403).json({ 
        message: user.status === "pending" 
          ? "Your account is pending approval." 
          : `Your account is ${user.status}.` 
      });
    }

    // Verify OTP
    if (user.otp !== otp || user.otpExpiry < new Date()) {
      return res.status(401).json({ message: "Invalid or expired OTP" });
    }

    // Clear OTP after success
    user.otp = undefined;
    user.otpExpiry = undefined;

    const accessToken = generateAccessToken(user, "user");
    const refreshToken = generateRefreshToken(user, "user");

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Fetch society name
    const society = await Society.findById(user.societyId);

    // Cache user session in Redis (TTL: 1 hour)
    const sessionData = {
      id: user._id,
      societyId: user.societyId,
      mobile: user.mobile,
      displayName: user.displayName,
      email: user.email,
      profile: user.profile,
      role: user.role,
      preferences: user.preferences,
      type: "user"
    };
    await redisClient.set(`user:${user._id}`, JSON.stringify(sessionData), "EX", 3600);

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        societyId: user.societyId,
        societyName: society ? society.name : "Unknown Society",
        mobile: user.mobile,
        displayName: user.displayName,
        profile: user.profile,
        preferences: user.preferences,
        type: "user"
      }
    });



  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /users/:userId
 * Get user profile.
 * Access: User (self) or Staff/Admin
 */
export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    // RBAC: Check if the requester is the user themselves OR an admin/staff
    const isSelf = req.userType === "user" && req.user._id.toString() === userId;
    const isPrivileged = req.userType === "admin" || req.userType === "staff";

    if (!isSelf && !isPrivileged) {
      return res.status(403).json({ message: "Access denied. You can only view your own profile." });
    }

    const user = await User.findById(userId, { password: 0, refreshToken: 0 });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /users
 * List users for a society.
 * Access: Staff/Admin
 */
export const getUsers = async (req, res) => {
  try {
    const { societyId, flat, status, page = 1, limit = 10 } = req.query;

    // RBAC: Only staff and admins can list users
    if (req.userType !== "admin" && req.userType !== "staff") {
      return res.status(403).json({ message: "Access denied. Staff or Admin privileges required." });
    }

    // Build filter
    const filter = {};

    // Logic for society scoping:
    if (req.userType === "staff") {
      // Staff are always restricted to their own society
      filter.societyId = req.user.societyId;
    } else if (req.userType === "admin") {
      // Admins (Superadmins) can view all or filter by a specific societyId if provided
      if (societyId) {
        filter.societyId = societyId;
      }
    }

    if (flat) filter["profile.flat"] = flat;
    if (status) filter.status = status;

    // Pagination
    const skip = (page - 1) * limit;

    const users = await User.find(filter, { password: 0, refreshToken: 0 })
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(filter);

    res.json({
      users,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PUT /users/:userId
 * Update a user profile.
 * Access: User (self) or Staff/Admin
 */
export const updateUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = req.body;

    // RBAC: Check if the requester is the user themselves OR an admin/staff
    const isSelf = req.userType === "user" && req.user._id.toString() === userId;
    const isPrivileged = req.userType === "admin" || req.userType === "staff";

    if (!isSelf && !isPrivileged) {
      return res.status(403).json({ message: "Access denied. You can only update your own profile." });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Security: Only privileged users can update status, role, or societyId
    if (!isPrivileged) {
      delete updates.status;
      delete updates.role;
      delete updates.societyId;
    }

    // If password is being updated, hash it
    if (updates.password) {
      const salt = await bcrypt.genSalt(10);
      updates.password = await bcrypt.hash(updates.password, salt);
    }

    // Apply updates
    Object.assign(user, updates);
    await user.save();

    res.json({
      message: "User updated successfully",
      user: {
        id: user._id,
        societyId: user.societyId,
        email: user.email,
        mobile: user.mobile,
        displayName: user.displayName,
        role: user.role,
        status: user.status,
        profile: user.profile
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * DELETE /users/:userId
 * Soft-delete a user.
 * Access: Admin
 */
  export const deleteUser = async (req, res) => {
  try {
    // RBAC: Only admins can delete users
    if (req.userType !== "admin") {
      return res.status(403).json({ message: "Access denied. Admin privileges required." });
    }

    const { userId } = req.params;
    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /users/:userId/approve
 * Approve or deny a user registration.
 * Access: Staff/Admin
 */
export const approveUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { action, comments } = req.body;

    // RBAC: Only staff and admins can approve users
    if (req.userType !== "admin" && req.userType !== "staff") {
      return res.status(403).json({ message: "Access denied. Staff or Admin privileges required." });
    }

    if (!["approve", "deny"].includes(action)) {
      return res.status(400).json({ message: "Invalid action. Use 'approve' or 'deny'." });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (action === "approve") {
      user.status = "active";
      user.approvedBy = req.user._id;
      user.approvedAt = new Date();
    } else {
      user.status = "deleted";
    }

    await user.save();

    res.json({ 
      message: `User registration ${action}d successfully`,
      status: user.status
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /users/create-resident
 * Admin creates a new resident (active immediately).
 * Access: Admin only
 */
export const createResident = async (req, res) => {
  try {
    // RBAC: Only admins can create residents directly
    if (req.userType !== "admin") {
      return res.status(403).json({ message: "Access denied. Admin privileges required." });
    }

    const { societyId, email, mobile, displayName, password, profile, flat, tower, role } = req.body;

    if (!societyId || !mobile || !displayName) {
      return res.status(400).json({ message: "Missing required fields (societyId, mobile, displayName)" });
    }

    // Validation: Check if block/flat exist if they are provided
    if (tower || flat) {
      const society = await Society.findById(societyId);
      if (!society) {
        return res.status(404).json({ message: "Society not found" });
      }

      if (tower) {
        const towerData = society.structure.find(s => s.block === tower);
        if (!towerData) {
          console.warn(`[WARNING] Tower ${tower} not found in society structure. Proceeding anyway.`);
        } else if (flat && !towerData.flats.includes(flat)) {
          console.warn(`[WARNING] Flat ${flat} not found in tower ${tower} structure. Proceeding anyway.`);
        }
      } else if (flat) {
        const flatExists = society.structure.some(s => s.flats.includes(flat));
        if (!flatExists) {
          console.warn(`[WARNING] Flat ${flat} not found in any tower structure. Proceeding anyway.`);
        }
      }
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { mobile },
        ...(email ? [{ email }] : [])
      ]
    });

    if (existingUser) {
      return res.status(409).json({ message: "User with this mobile or email already exists" });
    }

    let hashedPassword = undefined;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    const userProfile = profile || {};
    if (flat) userProfile.flat = flat;
    if (tower) userProfile.tower = tower;

    let userRole = ["resident"];
    if (role) {
      userRole = Array.isArray(role) ? role : [role.toLowerCase()];
    }

    const newUser = new User({
      societyId,
      email,
      mobile,
      displayName,
      password: hashedPassword,
      role: userRole,
      profile: userProfile,
      status: "active", // Active immediately when created by Admin
      approvedBy: req.user._id,
      approvedAt: new Date()
    });

    await newUser.save();

    res.status(201).json({
      message: "Resident created successfully",
      user: {
          _id: newUser._id,
          societyId: newUser.societyId,
          displayName: newUser.displayName,
          mobile: newUser.mobile,
          email: newUser.email,
          role: newUser.role,
          profile: newUser.profile,
          status: newUser.status
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /users/:userId/promote
 * Promote a resident to an Admin.
 * Access: Superadmin only
 */
export const promoteToAdmin = async (req, res) => {
  try {
    // RBAC: Only superadmins can promote users to admins
    if (req.userType !== "admin" || !req.user.isSuperadmin) {
      return res.status(403).json({ message: "Access denied. Superadmin privileges required." });
    }

    const { userId } = req.params;
    const { roleId, password } = req.body;

    if (!roleId) {
      return res.status(400).json({ message: "roleId is required for promotion" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if admin with this email or mobile already exists
    const existingAdmin = await Admin.findOne({
      $or: [
        ...(user.email ? [{ email: user.email }] : []),
        { mobile: user.mobile }
      ]
    });

    if (existingAdmin) {
      return res.status(409).json({ message: "An admin account already exists for this user's email or mobile" });
    }

    const adminPassword = password || user.password;
    if (!adminPassword) {
        return res.status(400).json({ message: "A password is required for admin accounts. Please provide one in the request body if the user doesn't have one." });
    }

    // Create new Admin record
    const newAdmin = new Admin({
      email: user.email || `${user.mobile}@gosociety.com`, // Email is required in Admin schema
      mobile: user.mobile,
      displayName: user.displayName,
      password: adminPassword,
      roleId: roleId,
      isSuperadmin: false
    });

    await newAdmin.save();

    res.status(200).json({
      message: "User promoted to admin successfully",
      adminId: newAdmin._id
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
/**
 * POST /users/:userId/token
 * Register or update notification token.
 * Access: User (self)
 */
export const registerNotificationToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    // Use findByIdAndUpdate because req.user might be a plain object from Redis
    await User.findByIdAndUpdate(req.user.id || req.user._id, { notificationToken: token });
    
    // Invalidate Redis cache to ensure consistency
    await redisClient.del(`user:${req.user.id || req.user._id}`);

    res.json({ message: "Notification token registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

