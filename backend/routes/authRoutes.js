const express = require("express");
const router = express.Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: "Too many login attempts. Please try again after 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many registration attempts. Please try again later." },
});

const getToken = (req) => {
  if (req.signedCookies?.token) return req.signedCookies.token;
  if (req.cookies?.token) return req.cookies.token;
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.replace('Bearer ', '');
  }
  return null;
};

router.post("/register", registerLimiter, async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    const sanitizedEmail = email?.toLowerCase().trim();
    const sanitizedFirstName = firstName?.trim() || '';
    const sanitizedLastName = lastName?.trim() || '';

    if (!sanitizedEmail || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const existingUser = await User.findOne({ email: sanitizedEmail });
    if (existingUser) {
      return res.status(409).json({
        error: "Email already registered",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters long",
      });
    }

    const user = new User({
      email: sanitizedEmail,
      passwordHash: password,
      firstName: sanitizedFirstName,
      lastName: sanitizedLastName,
      verificationToken: crypto.randomBytes(32).toString("hex"),
      verificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    await user.save();

    const token = user.generateAuthToken();

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.status(201).json({
      message: "User registered successfully",
      user: user.toJSON(),
      token,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      error: "Registration failed",
      message: error.message,
    });
  }
});

router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const sanitizedEmail = email?.toLowerCase().trim();

    if (!sanitizedEmail || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const user = await User.findOne({ email: sanitizedEmail });

    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(423).json({
        error: "Account locked",
        message: `Account is locked until ${user.lockedUntil}`,
      });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      user.loginAttempts += 1;

      if (user.loginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
      }

      await user.save();

      return res.status(401).json({
        error: "Invalid credentials",
        attemptsRemaining: 5 - user.loginAttempts,
      });
    }

    user.loginAttempts = 0;
    user.lockedUntil = undefined;
    user.lastLogin = new Date();
    await user.save();

    const token = user.generateAuthToken();

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.json({
      message: "Login successful",
      user: user.toJSON(),
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Login failed",
      message: error.message,
    });
  }
});

router.post("/logout", async (req, res) => {
  try {
    res.clearCookie("token", {
      path: "/",
    });
    res.json({
      message: "Logout successful",
    });
  } catch (error) {
    res.status(500).json({
      error: "Logout failed",
      message: error.message,
    });
  }
});

router.get("/profile", async (req, res) => {
  try {
    const token = getToken(req);
    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.json({
      user: user.toJSON(),
    });
  } catch (error) {
    console.error("Profile error:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        error: "Invalid token",
      });
    }
    res.status(500).json({
      error: "Failed to get profile",
      message: error.message,
    });
  }
});

router.get("/dashboard", async (req, res) => {
  try {
    const token = getToken(req);
    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.json({
      user: user.toJSON(),
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        error: "Invalid token",
        message: "Please login again",
      });
    }
    res.status(500).json({
      error: "Failed to load dashboard",
      message: error.message,
    });
  }
});

router.put("/change-password", async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: "Current password and new password are required",
      });
    }

    const token = getToken(req);
    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isValid = await user.comparePassword(currentPassword);
    if (!isValid) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        error: "New password must be at least 8 characters long",
      });
    }

    user.passwordHash = newPassword;
    await user.save();

    res.json({
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      error: "Failed to change password",
      message: error.message,
    });
  }
});

module.exports = router;