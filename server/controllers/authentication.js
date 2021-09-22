const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/user");
const sendgrid = require("../config/sendgrid");
const { setUserInfo } = require("../helpers");
const { getRole } = require("../helpers");
const Token = require("../models/token");
require("dotenv/config");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate JWT
// TO-DO Add issuer and audience
function generateToken(user) {
  return jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: 604800 // in seconds
  });
}

//= =======================================
// Login Route
//= =======================================
exports.login = async (req, res, next) => {
  const { email } = req.body;
  const { password } = req.body;
  try {
    const user = await User.findOne({ email })
      .populate("profile.org")
      .populate("profile.location");
    if (!user) {
      return res.status(401).json({ error: "No user with the email" });
    }
    user.comparePassword(password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ error: "Password mismatch" });
      }
      const userInfo = setUserInfo(user);
      if (!userInfo.verified) {
        return res
          .status(422)
          .send({ error: "Your account is not verified yet" });
      }
      if (getRole(userInfo.role) === 3) {
        return res
          .status(422)
          .send({ error: "Your account is not authorized" });
      }
      const result = {
        token: `JWT ${generateToken(userInfo)}`,
        user: userInfo
      };
      return res.status(200).json(result);
    });

    return res.status(401).json({ error: "No user with the email" });
  } catch (err) {
    return next(err);
  }
};

//= =======================================
// Social Login Route
//= =======================================
exports.socialLogin = async (req, res, next) => {
  const { token } = req.body;
  try {
    if (req.params.provider === "google") {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      const {
        // eslint-disable-next-line camelcase,no-unused-vars
        email, given_name, family_name
      } = ticket.getPayload();

      let user = await User.findOne({ email });
      if (user) {
        user = await User.findOneAndUpdate(
          { _id: user._id },
          {
            profile: {
              first_name: given_name,
              last_name: family_name
            },
            provider: "google"
          }
        );

        const userInfo = setUserInfo(user);
        const result = {
          token: `JWT ${generateToken(userInfo)}`,
          user: userInfo
        };
        return res.status(200).json(result);
      }

      const newUser = new User({
        email,
        profile: {
          first_name: given_name,
          last_name: family_name
        },
        verified: true,
        provider: "google"
      });
      const usr = await newUser.save();
      const userInfo = setUserInfo(usr);
      const result = {
        token: `JWT ${generateToken(userInfo)}`,
        user: userInfo
      };
      return res.status(200).json(result);
    }

    return res.status(400).json({ error: "No matched social provider" });
  } catch (err) {
    return next(err);
  }
};

//= =======================================
// Registration Route
//= =======================================
exports.participantRegister = async function (req, res, next) {
  const { email } = req.body;
  // eslint-disable-next-line camelcase
  const { first_name } = req.body;
  // eslint-disable-next-line camelcase
  const { last_name } = req.body;
  const { password } = req.body;

  try {
    const users = await User.find({ email });
    if (users.length > 0) {
      return res
        .status(422)
        .send({ error: "That email address is already in use." });
    }
    const user = new User({
      email,
      password,
      profile: {
        first_name,
        last_name
      }
    });
    const usr = await user.save();
    const userInfo = setUserInfo(usr);
    const token = new Token({
      _userId: userInfo._id,
      token: crypto.randomBytes(16).toString("hex")
    });
    token.save();
    sendgrid.userEmailVerification(
      userInfo.email,
      `${userInfo.profile.firstName} ${userInfo.profile.lastName} `,
      token.token
    );
    return res.status(201).json({ user: userInfo });
  } catch (err) {
    return next(err);
  }
};

exports.confirmEmail = async (req, res, next) => {
  const { token } = req.body;
  try {
    const t = await Token.findOne({ token });
    if (!t) {
      return res.status(201).json({
        message: "Invalid token for email verification"
      });
    }
    // eslint-disable-next-line no-underscore-dangle
    const result = await User.findById(t._userId);
    if (!result) {
      return res.status(201).json({
        message: "Invalid token for email verification"
      });
    }
    if (result.verified) {
      return res.status(201).json({
        message: "The account has already been verified"
      });
    }
    result.verified = true;
    result.save();
    return res.status(201).json({
      message: "The account has been verified successfully"
    });
  } catch (err) {
    return next(err);
  }
};

//= =======================================
// Authorization Middleware
//= =======================================

// Role authorization check
exports.roleAuthorization = function (requiredRole) {
  return function (req, res, next) {
    const { user } = req;

    User.findById(user._id, (err, foundUser) => {
      if (err) {
        res.status(422).json({ error: "No user was found." });
        return next(err);
      }

      // If user is found, check role.
      if (getRole(foundUser.role) >= getRole(requiredRole)) {
        return next();
      }

      return res
        .status(401)
        .json({ error: "You are not authorized to view this content." });
    });
  };
};

//= =======================================
// Forgot Password Route
//= =======================================

exports.forgotPassword = async (req, res, next) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      let token = new Token({
        _userId: user._id,
        token: crypto.randomBytes(16).toString("hex")
      });
      token = await token.save();
      sendgrid.userForgotPasword(email, token.token);
      return res.status(200).json({
        message: "Please check your email for the link to reset your password."
      });
    }
    return res.status(422).json({
      error:
        "Your request could not be processed with the email. Please try again."
    });
  } catch (err) {
    return next(err);
  }
};

//= =======================================
// Reset Password Route
//= =======================================

exports.verifyToken = function (req, res, next) {
  Token.findOne({ token: req.params.token }, (err, token) => {
    if (err || !token) {
      return res.status(422).json({
        error:
          "Your token has expired. Please attempt to reset your password again."
      });
    }
    // eslint-disable-next-line no-underscore-dangle
    User.findById(token._userId, (findErr, user) => {
      if (findErr) {
        return next(findErr);
      }
      // eslint-disable-next-line no-param-reassign
      user.password = req.body.password;
      user.save((saveErr) => {
        if (saveErr) {
          return next(saveErr);
        }
        return res.status(200).json({
          message:
              "Password changed successfully. Please login with your new password."
        });
      });

      return next();
    });
  });
};

exports.resetPasswordSecurity = async (req, res, next) => {
  try {
    const user = await User.findById(req.body.userid);
    user.password = req.body.password;
    await user.save();
    return res.status(200).json({
      message:
        "Password changed successfully. Please login with your new password."
    });
  } catch (err) {
    return next(err);
  }
};

exports.resendVerification = function (req, res, next) {
  const { _id, email, name } = req.body;
  const token = new Token({
    _userId: _id,
    token: crypto.randomBytes(16).toString("hex")
  });
  token.save((err) => {
    if (err) {
      return res.status(500).send({ error: err.message });
    }
    sendgrid.userEmailVerification(email, name, token.token);

    return res.status(200);
  });

  return next();
};
