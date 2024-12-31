const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const authSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: /.+\@.+\..+/,
    },
    password: {
      type: String,
      required: true,
    },
    theme: {
      type: String,
    },
    accessibleWorkspace: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          required: true,
        },
        workspaceAccessToken: {
          type: String,
          required: true,
        },
      },
    ],
  },
  { timestamps: true }
);

authSchema.pre("save", async function (next) {
  const user = this;

  if (user.isModified("password")) {
    user.password = await bcrypt.hash(user.password, 12);
  }
  next();
});

authSchema.methods.comparePassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

authSchema.statics.login = async function (identifier, password) {
  const user = await this.findOne(
    {
      $or: [{ username: identifier }, { email: identifier }],
    },
    { password: 1 },
    { refreshToken: 1 }
  );

  if (!user) {
    throw new Error("User not found");
  }
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new Error("Incorrect password");
  }

  return user._id;
};

const User = mongoose.model("User", authSchema);
module.exports = User;
