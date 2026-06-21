const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  passwordHash: {
    type: String,
    required: true
  },
  salt: {
    type: String,
    default: ''
  },
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockedUntil: Date,
  lastLogin: Date,
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('passwordHash')) return next();
  
  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.salt = salt;
    this.passwordHash = await bcrypt.hash(this.passwordHash + this.salt, this.salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword + this.salt, this.passwordHash);
  } catch (error) {
    console.error('Password comparison error:', error);
    return false;
  }
};

userSchema.methods.generateAuthToken = function() {
  const jwt = require('jsonwebtoken');
  const token = jwt.sign(
    { 
      id: this._id, 
      email: this.email,
      role: this.role
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
  return token;
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.salt;
  delete user.verificationToken;
  delete user.resetPasswordToken;
  delete user.__v;
  return user;
};

const User = mongoose.model('User', userSchema);
module.exports = User;