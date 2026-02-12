import Staff from "../models/Staff.js";
import Society from "../models/Society.js";
import { generateAccessToken, generateRefreshToken } from "../config/jwt.js";
import { sendSMS } from "../utils/sms.js";
import redisClient from "../config/redis.js";


/**
 * POST /staff/send-otp
 * Send OTP to staff's mobile.
 * Access: Public
 */
export const sendOtp = async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({ message: "Mobile number is required" });
    }

    const staff = await Staff.findOne({ mobile });

    if (!staff) {
      return res.status(404).json({ message: "Staff not found with this mobile number" });
    }

    if (staff.status !== "active") {
        return res.status(403).json({ message: `Account is ${staff.status}` });
    }

    // Generate 4 digit OTP (for testing, we'll use 1234 or random)
    const otp = "1234";
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

    staff.otp = otp;
    staff.otpExpiry = otpExpiry;
    await staff.save();

    // In production, integrate with SMS gateway here
    console.log(`OTP for Staff ${mobile}: ${otp}`);
    
    // Attempt to send real SMS
    await sendSMS(mobile, otp);

    res.json({ message: "OTP sent successfully", otp: process.env.NODE_ENV === 'development' ? otp : undefined });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /staff/login
 * Staff (Guard) login using OTP.
 * Access: Public
 */
export const loginStaff = async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({ message: "Missing mobile or otp" });
    }

    const staff = await Staff.findOne({ mobile });

    if (!staff) {
      return res.status(401).json({ message: "Invalid mobile or otp" });
    }

    if (staff.status !== "active") {
      return res.status(403).json({ message: `Your account is ${staff.status}.` });
    }

    // Restrict access to only guards for the app
    if (staff.role !== 'guard') {
        return res.status(403).json({ message: "Access denied. Only security guards can login to this app." });
    }

    // Verify OTP
    if (staff.otp !== otp || staff.otpExpiry < new Date()) {
      return res.status(401).json({ message: "Invalid or expired OTP" });
    }

    // Clear OTP after success
    staff.otp = undefined;
    staff.otpExpiry = undefined;

    // Generate tokens - using "staff" type as per jwt.js config
    const accessToken = generateAccessToken(staff, "staff");
    const refreshToken = generateRefreshToken(staff, "staff");

    // Fetch society name
    const society = await Society.findById(staff.societyId);

    // Cache staff session in Redis (TTL: 1 hour)
    const sessionData = {
      id: staff._id,
      societyId: staff.societyId,
      mobile: staff.mobile,
      displayName: staff.displayName,
      email: staff.email,
      role: staff.role,
      preferences: staff.preferences,
      type: "staff"
    };
    await redisClient.set(`user:${staff._id}`, JSON.stringify(sessionData), "EX", 3600);

    // Return response matching the structure expected by frontend
    res.json({
      accessToken,
      refreshToken,
      user: {
        id: staff._id,
        societyId: staff.societyId,
        societyName: society ? society.name : "Unknown Society",
        mobile: staff.mobile,
        displayName: staff.displayName,
        email: staff.email,
        role: staff.role, 
        preferences: staff.preferences,
        type: "staff"
      }
    });


  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /staff
 * Create a new staff member (Guard, etc.).
 * Access: Admin only
 */
export const createStaff = async (req, res) => {
  try {
    const { societyId, email, mobile, displayName, password, role } = req.body;

    if (!societyId || !email || !mobile || !displayName || !password || !role) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if staff with email or mobile already exists
    const existingStaff = await Staff.findOne({
      $or: [{ email }, { mobile }]
    });

    if (existingStaff) {
      return res.status(409).json({ message: "Staff with this email or mobile already exists" });
    }

    // Hash password
    const bcrypt = await import("bcryptjs");
    const salt = await bcrypt.default.genSalt(10);
    const hashedPassword = await bcrypt.default.hash(password, salt);

    const newStaff = new Staff({
      societyId,
      email,
      mobile,
      displayName,
      password: hashedPassword,
      role,
      status: "active"
    });

    await newStaff.save();

    res.status(201).json({
      message: "Staff member created successfully",
      staff: {
        id: newStaff._id,
        societyId: newStaff.societyId,
        email: newStaff.email,
        mobile: newStaff.mobile,
        displayName: newStaff.displayName,
        role: newStaff.role,
        status: newStaff.status
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /staff
 * Get all staff members.
 * Access: Admin only
 */
export const getAllStaff = async (req, res) => {
  try {
    const { societyId } = req.query;
    const filter = societyId ? { societyId } : {};

    const staffList = await Staff.find(filter, { password: 0, otp: 0, otpExpiry: 0 });

    res.json(staffList);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PATCH /staff/preferences
 * Update access logged-in staff's preferences.
 */
export const updateMyPreferences = async (req, res) => {
  try {
    const staffId = req.user.id;
    const { language, theme } = req.body;

    const updates = {};
    if (language) updates["preferences.language"] = language;
    if (theme) updates["preferences.theme"] = theme;

    const staff = await Staff.findByIdAndUpdate(
        staffId, 
        { $set: updates }, 
        { new: true }
    ).select("-password -otp -otpExpiry");

    if (!staff) return res.status(404).json({ message: "Staff not found" });

    res.json(staff);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /staff/:staffId
 * Get a single staff member by ID.
 * Access: Admin only
 */
export const getStaffById = async (req, res) => {
  try {
    const { staffId } = req.params;
    const staff = await Staff.findById(staffId, { password: 0, otp: 0, otpExpiry: 0 });

    if (!staff) {
      return res.status(404).json({ message: "Staff member not found" });
    }

    res.json(staff);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PUT /staff/:staffId
 * Update a staff member.
 * Access: Admin only
 */
export const updateStaff = async (req, res) => {
  try {
    const { staffId } = req.params;
    const updates = req.body;

    // Remove sensitive fields if they try to update them directly
    delete updates.password;
    delete updates.otp;
    delete updates.otpExpiry;

    const staff = await Staff.findByIdAndUpdate(
      staffId,
      { $set: updates },
      { new: true }
    ).select("-password -otp -otpExpiry");

    if (!staff) {
      return res.status(404).json({ message: "Staff member not found" });
    }

    res.json({
      message: "Staff member updated successfully",
      staff
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * DELETE /staff/:staffId
 * Delete a staff member.
 * Access: Admin only
 */
export const deleteStaff = async (req, res) => {
  try {
    const { staffId } = req.params;
    const staff = await Staff.findByIdAndDelete(staffId);

    if (!staff) {
      return res.status(404).json({ message: "Staff member not found" });
    }

    res.json({ message: "Staff member deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
/**
 * POST /staff/:staffId/token
 * Register or update notification token for staff.
 */
export const registerNotificationToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    // Use findByIdAndUpdate because req.user might be a plain object from Redis
    await Staff.findByIdAndUpdate(req.user.id || req.user._id, { notificationToken: token });
    
    // Invalidate Redis cache
    await redisClient.del(`user:${req.user.id || req.user._id}`);

    res.json({ message: "Staff notification token registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
