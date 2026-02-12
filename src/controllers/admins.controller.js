import Admin from "../models/Admin.js";
import bcrypt from "bcryptjs";

/**
 * POST /admins
 * Create a new admin.
 * Access: Superadmin only
 */
export const createAdmin = async (req, res) => {
  try {
    // RBAC: Any admin can create another admin
    if (req.userType !== 'admin') {
      return res.status(403).json({ message: "Access denied. Admin privileges required." });
    }

    const { email, mobile, displayName, password, roleId, isSuperadmin } = req.body;

    // Only superadmins can create other superadmins
    if (isSuperadmin && !req.user.isSuperadmin) {
      return res.status(403).json({ message: "Only superadmins can create other superadmins." });
    }

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
      isSuperadmin: isSuperadmin || false // Default to false if not provided
    });

    await newAdmin.save();

    res.status(201).json({ 
        message: "Admin created successfully", 
        adminId: newAdmin._id,
        admin: {
            id: newAdmin._id,
            email: newAdmin.email,
            mobile: newAdmin.mobile,
            displayName: newAdmin.displayName,
            roleId: newAdmin.roleId,
            isSuperadmin: newAdmin.isSuperadmin
        }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /admins
 * Get all admins.
 * Access: Superadmin only
 */
export const getAllAdmins = async (req, res) => {
  try {
    // Check if the requester is a superadmin
    if (!req.user || !req.user.isSuperadmin) {
        return res.status(403).json({ message: "Access denied. Superadmin privileges required." });
    }

    const admins = await Admin.find({}, { password: 0, refreshToken: 0 });

    res.json(admins);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /admins/:adminId
 * Get a single admin by ID.
 * Access: Superadmin only
 */
export const getAdminById = async (req, res) => {
  try {
    // Check if the requester is a superadmin
    if (!req.user || !req.user.isSuperadmin) {
        return res.status(403).json({ message: "Access denied. Superadmin privileges required." });
    }

    const { adminId } = req.params;
    const admin = await Admin.findById(adminId, { password: 0, refreshToken: 0 });

    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    res.json(admin);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PUT /admins/:adminId
 * Update an admin by ID.
 * Access: Superadmin only
 */
export const updateAdmin = async (req, res) => {
  try {
    // Check if the requester is a superadmin
    if (!req.user || !req.user.isSuperadmin) {
        return res.status(403).json({ message: "Access denied. Superadmin privileges required." });
    }

    const { adminId } = req.params;
    const updates = req.body;

    // Check if admin exists
    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    // If password is being updated, hash it
    if (updates.password) {
      const salt = await bcrypt.genSalt(10);
      updates.password = await bcrypt.hash(updates.password, salt);
    }

    // Check for unique email/mobile if they are being updated
    if (updates.email || updates.mobile) {
      const existingAdmin = await Admin.findOne({
        _id: { $ne: adminId },
        $or: [
          ...(updates.email ? [{ email: updates.email }] : []),
          ...(updates.mobile ? [{ mobile: updates.mobile }] : [])
        ]
      });

      if (existingAdmin) {
        return res.status(409).json({ message: "Admin with this email or mobile already exists" });
      }
    }

    // Apply updates
    Object.assign(admin, updates);
    await admin.save();

    res.json({
        message: "Admin updated successfully",
        admin: {
            id: admin._id,
            email: admin.email,
            mobile: admin.mobile,
            displayName: admin.displayName,
            roleId: admin.roleId,
            isSuperadmin: admin.isSuperadmin,
            status: admin.status
        }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /admins/:adminId/token
 * Register or update notification token for admin.
 */
export const registerNotificationToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    // Use findByIdAndUpdate because req.user might be a plain object from Redis
    await Admin.findByIdAndUpdate(req.user.id || req.user._id, { notificationToken: token });
    
    // Invalidate Redis cache
    await redisClient.del(`user:${req.user.id || req.user._id}`);

    res.json({ message: "Admin notification token registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};