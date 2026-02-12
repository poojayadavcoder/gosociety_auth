import jwt from "jsonwebtoken";

export const generateAccessToken = (user, type) => {
  return jwt.sign(
    { 
      id: user._id, 
      societyId: user.societyId,
      type 
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "24h" }
  );
};


export const generateRefreshToken = (user, type) => {
  return jwt.sign(
    { id: user._id, type },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
};
