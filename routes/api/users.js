const express = require("express");
const CreateError = require("http-errors");
const path = require("path");
const fs = require("fs").promises;
const Jimp = require("jimp");

const router = express.Router();

const { User, schemas } = require("../../models/user");
const { PORT } = process.env;
const { sendMail } = require("../../helpers");

const { authenticate, upload } = require("../../middlewares");

const avatarsDir = path.join(__dirname, "../../", "public", "avatars");

router.post("/verify", async (req, res, next) => {
  try {
    const { error } = schemas.verify.validate(req.body);
    if (error) {
      throw new CreateError(error.message);
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (user.verify) {
      throw new CreateError(400, "Verification has already been passed");
    }
    const mail = {
      to: email,
      subject: "SENDGRID mail verification",
      html: `<a target="_blank" href='http://localhost:${PORT}/api/users/verify/${user.verificationToken}'>Please confirm you email!</a>`,
    };
    await sendMail(mail);
    res.json({
      message: "Verification email sent",
    });
  } catch (error) {
    next(error);
  }
});

router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const { verificationToken } = req.params;
    const user = User.findOne({ verificationToken });
    if (!user) {
      throw new CreateError(404, "Not found");
    }
    await User.findByIdAndUpdate(user._id, {
      verificationToken: "",
      verify: true,
    });
    res.json({
      message: "Verification successful",
    });
  } catch (error) {
    next(error);
  }
});

router.patch(
  "/avatars",
  authenticate,
  upload.single("avatar"),
  async (req, res, next) => {
    if (!req.file) {
      throw new CreateError(400, "File upload error!");
    }
    const host = `${req.protocol}://${req.headers.host}`;
    const { _id } = req.user;
    const { path: tempUpload, filename } = req.file;
    const [extention] = filename.split(".").reverse();
    const newFileName = `${_id}.${extention}`;
    const resultUpload = path.join(avatarsDir, newFileName);
    try {
      const image = await Jimp.read(tempUpload);
      await image.resize(250, 250);
      await image.write(tempUpload);
      await fs.rename(tempUpload, resultUpload);

      const avatarURL = path.join(host, "avatars", newFileName);
      await User.findByIdAndUpdate(_id, { avatarURL });
      res.json({
        avatarURL,
      });
    } catch (error) {
      next(error);
    }
  }
);

router.get("/current", authenticate, async (req, res, next) => {
  try {
    res.json({
      email: req.user.email,
      subscription: req.user.subscription,
    });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authenticate, async (req, res, next) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });
  res.status(204).send();
});

router.patch("/", authenticate, async (req, res, next) => {
  try {
    const { error } = schemas.patchSubscription.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const { _id } = req.user;
    const result = await User.findByIdAndUpdate(_id, req.body, {
      new: true,
      select: "-_id email subscription",
    });
    if (!result) {
      throw new CreateError(404, "Not found");
    }
    res.json(result);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
