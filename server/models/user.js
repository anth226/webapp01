// Importing Node packages required for schema
const mongoose = require("mongoose");
const { ROLE_MEMBER } = require("../constants");
const { ROLE_BLOCK } = require("../constants");
const { ROLE_ADMIN } = require("../constants");

const { Schema } = mongoose;
const { translateP } = require("../helpers");

//= ===============================
// User Schema
//= ===============================
const UserSchema = new Schema(
  {
    email: {
      type: String,
      lowercase: true,
      unique: true,
      required: true
    },
    password: {
      type: String
    },
    profile: {
      first_name: { type: String, required: true },
      last_name: { type: String, required: true },
      photo: { type: String },
      address: { type: String },
      country: { type: String },
      phone: { type: String },
      personal_statement: { type: String },
      twitter: { type: String },
      linkedin: { type: String },
      facebook: { type: String },
      web: { type: String },
      tags: [{ type: Schema.Types.ObjectId, ref: "FieldData" }],
      contact: { type: String },
      position: { type: String }
    },
    role: {
      type: String,
      enum: [ROLE_MEMBER, ROLE_BLOCK, ROLE_ADMIN],
      default: ROLE_MEMBER
    },
    blockers: [{ type: Schema.Types.ObjectId, ref: "User" }],
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    verified: { type: Boolean }
  },
  {
    timestamps: true
  }
);

//= ===============================
// User ORM Methods
//= ===============================

// Pre-save of user to database, hash password if password is modified or new
UserSchema.pre("save", (next) => {
  const user = this;
  if (!user.isModified("password")) return next();
  user.password = translateP(user.password);
  return next();
});

// Method to compare password for login
UserSchema.methods.comparePassword = (candidatePassword, cb) => {
  const cp = translateP(candidatePassword);
  const isMatch = cp === this.password;
  cb(null, isMatch);
};

module.exports = mongoose.model("User", UserSchema);
