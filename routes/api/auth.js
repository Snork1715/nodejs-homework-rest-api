const express = require("express");
const CreateError = require("http-errors");
const { v4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");

const router = express.Router();

const { User, schemas } = require("../../models/user");
const { sendMail } = require("../../helpers");

const { SECRET_KEY, PORT } = process.env;

router.post("/register", async (req, res, next) => {
  try {
    const { error } = schemas.register.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      throw new CreateError(409, { message: "Email in use" });
    }
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);
    const avatarURL = gravatar.url(email, { protocol: "http", s: "250" });
    const verificationToken = v4();
    const result = await User.create({
      avatarURL,
      email,
      verificationToken,
      password: hashPassword,
    });

    const mail = {
      to: email,
      subject: "SENDGRID mail verification",
      html: `<a target="_blank" href='http://localhost:${PORT}/api/users/verify/${verificationToken}'>Please confirm you email!</a>`,
    };

    await sendMail(mail);

    res.status(201).json({
      user: {
        email,
        subscription: result.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { error } = schemas.register.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw new CreateError(401, "Email or password is wrong");
    }
    if (!user.verify) {
      throw new CreateError(401, "Email not verified");
    }
    const compareResult = await bcrypt.compare(password, user.password);
    if (!compareResult) {
      throw new CreateError(401, "Email or password is wrong");
    }
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "3h" });
    await User.findByIdAndUpdate(user._id, { token });
    res.json({
      token,
      user: {
        email,
      },
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
