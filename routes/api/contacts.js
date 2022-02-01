const express = require("express");
const CreateError = require("http-errors");
const router = express.Router();

const { Contact, schemas } = require("../../models/contact");

router.get("/", async (req, res, next) => {
  try {
    const result = await Contact.find({}, "-createdAt -updatedAt");
    res.json(result);
  } catch (error) {
    next(error);
  }
});

router.get("/:contactId", async (req, res, next) => {
  try {
    const { contactId } = req.params;
    const result = await Contact.findById(contactId);
    if (!result) {
      throw new CreateError(404, "Not found");
    }
    res.json(result);
  } catch (error) {
    if (error.message.includes("Cast to ObjectId failed")) {
      error.status = 400;
    }
    next(error);
  }
});

router.post("/", async (req, res, next) => {
  try {
    const { error } = schemas.add.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const result = await Contact.create(req.body);
    res.status(201).json(result);
  } catch (error) {
    if (error.message.includes("validation failed")) {
      error.status = 400;
    }
    next(error);
  }
});

router.delete("/:contactId", async (req, res, next) => {
  try {
    const { contactId } = req.params;
    const result = await Contact.findByIdAndDelete(contactId);
    if (!result) {
      throw new CreateError(404, "Not found");
    }
    res.json({ message: "contact deleted" });
  } catch (error) {
    if (error.message.includes("Cast to ObjectId failed")) {
      error.status = 400;
    }
    next(error);
  }
});

router.put("/:contactId", async (req, res, next) => {
  try {
    if (!req.body) {
      throw new CreateError(404, "missing fields");
    }
    const { error } = schemas.add.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const { contactId } = req.params;
    const result = await Contact.findByIdAndUpdate(contactId, req.body, {
      new: true,
    });
    if (!result) {
      throw new CreateError(404, "Not found");
    }
    res.json(result);
  } catch (error) {
    if (error.message.includes("Cast to ObjectId failed")) {
      error.status = 400;
    }
    next(error);
  }
});

router.patch("/:contactId/favorite", async (req, res, next) => {
  try {
    if (!req.body) {
      throw new CreateError(400, "missing field favorite");
    }
    const { error } = schemas.patchFavorite.validate(req.body);
    if (error) {
      throw new CreateError(400, error.message);
    }
    const { contactId } = req.params;
    const result = await Contact.findByIdAndUpdate(contactId, req.body, {
      new: true,
    });
    if (!result) {
      throw new CreateError(404, "Not found");
    }
    res.json(result);
  } catch (error) {
    if (error.message.includes("Cast to ObjectId failed")) {
      error.status = 400;
    }
    next(error);
  }
});

module.exports = router;
