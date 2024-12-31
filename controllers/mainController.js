const express = require("express");
const mongoose = require("mongoose");
const User = require("../models/userModel");
const Folder = require("../models/folderModel");
const Form = require("../models/formModel");
const Response = require("../models/responseModel");
const Analytics = require("../models/analyticsModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const jwtExpiresIn = "7200m";

const generateAccessToken = (email, permission) => {
  return jwt.sign(
    { email, permission },
    process.env.WORKSPACE_ACCESS_TOKEN_SECRET,
    {
      expiresIn: jwtExpiresIn,
    }
  );
};

const addWorkSpaces = async (req, res) => {
  const { id } = req.params;

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  const { email, permission } = req.body;
  console.log(email, permission);
  if (!email || !permission) {
    return res
      .status(400)
      .json({ error: "Email and permission are required." });
  }

  try {
    const recipient = await User.findOne({ email });
    if (!recipient) {
      return res
        .status(404)
        .json({ error: "User with provided email not found." });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    let workspaceAccessToken;
    try {
      workspaceAccessToken = generateAccessToken(user.email, permission);
    } catch (error) {
      console.error("Error generating access token:", error);
      return res
        .status(500)
        .json({ error: "Failed to generate access token." });
    }

    if (!recipient.accessibleWorkspace) {
      recipient.accessibleWorkspace = [];
    }

    const workspaceExists = recipient.accessibleWorkspace.some(
      (workspace) => workspace.userId.toString() === userId.toString()
    );

    if (workspaceExists) {
      return res
        .status(400)
        .json({ error: "Workspace already shared with this user." });
    }

    recipient.accessibleWorkspace.push({
      userId: userId,
      workspaceAccessToken: workspaceAccessToken,
    });

    await recipient.save();
    console.log(recipient);
    return res.status(200).json({
      message: "Workspace shared successfully.",
      username: recipient.username,
    });
  } catch (error) {
    console.error("Error sharing workspace:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
};

const getWorkSpaces = async (req, res) => {
  const { id } = req.params;

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const accessibleWorkspace = user.accessibleWorkspace;

    const workspaceDetails = await Promise.all(
      accessibleWorkspace.map(async (workspace) => {
        try {
          const decodedToken = jwt.verify(
            workspace.workspaceAccessToken,
            process.env.WORKSPACE_ACCESS_TOKEN_SECRET
          );

          const email = decodedToken.email;
          const recipient = await User.findOne({ email });

          if (recipient) {
            return {
              userId: workspace.userId,
              username: recipient.username,
              permission: decodedToken.permission,
            };
          } else {
            return {
              userId: workspace.userId,
              error: `No user found for email: ${email}`,
            };
          }
        } catch (error) {
          console.error("Token verification error:", error.message);
          return {
            userId: workspace.userId,
            error: "Invalid or expired token.",
          };
        }
      })
    );

    const currentUserWorkspace = {
      userId: userId.toString(),
      username: user.username,
      permission: "edit",
    };

    workspaceDetails.unshift(currentUserWorkspace);

    return res.status(200).json({
      message: "Workspaces fetched successfully",
      workspaces: workspaceDetails,
    });
  } catch (error) {
    console.error("Error fetching workspaces:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const getUser = async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  const userIdFromParams = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userIdFromParams) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Access token is missing" });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userIdFromToken = decodedToken?.id;

    if (!mongoose.Types.ObjectId.isValid(userIdFromToken)) {
      return res.status(403).json({ message: "Invalid or corrupted token." });
    }

    if (
      !userIdFromParams.equals(new mongoose.Types.ObjectId(userIdFromToken))
    ) {
      const tokenUser = await User.findById(
        new mongoose.Types.ObjectId(userIdFromToken)
      );
      if (!tokenUser) {
        return res.status(404).json({ error: "User not found." });
      }

      const hasAccess = tokenUser.accessibleWorkspace.some((workspace) =>
        workspace.userId.equals(userIdFromParams)
      );

      if (!hasAccess) {
        return res.status(403).json({
          error: "Access denied: No permission to access this user.",
        });
      }
    }

    const user = await User.findById(userIdFromParams).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const folders = await Folder.find({
      userId: userIdFromParams,
    }).select("name -_id");

    const folderForms = {};

    for (const folder of folders) {
      const forms = await Form.find({
        userId: userIdFromParams,
        folderName: folder.name,
      }).select("formName -_id");

      folderForms[folder.name] = forms.map(
        (form) => form.formName.split("@")[0]
      );
    }

    const responseFolderForms = Object.keys(folderForms).reduce(
      (acc, folder) => {
        const cleanFolderName = folder.split("@")[0];
        acc[cleanFolderName] = folderForms[folder].map(
          (form) => form.split("@")[0]
        );
        return acc;
      },
      {}
    );

    res.status(200).json({
      user: user.toObject(),
      folders: folders.map((f) => f.name.split("@")[0]),
      folderForms: responseFolderForms,
    });
  } catch (error) {
    console.error("Error fetching user or validating access:", error.message);
    res.status(500).json({
      error:
        "An unexpected error occurred while fetching the user, folders, or forms.",
    });
  }
};

const updateUser = async (req, res) => {
  const { id } = req.params;
  const { username, email, password, newPassword, theme } = req.body;

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (password && newPassword) {
      const isMatch = await user.comparePassword(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid current password" });
      }

      user.password = newPassword;
      if (username) user.username = username;
      if (email) user.email = email;
    } else {
      if (username) user.username = username;
      if (email) user.email = email;
    }
    if (theme) {
      user.theme = theme;
    }
    await user.save();

    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res
      .status(500)
      .json({ error: "An error occurred while updating the user" });
  }
};
const createFolder = async (req, res) => {
  const { folderName } = req.body;
  const { id } = req.params; // userId

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  if (folderName.includes("@")) {
    return res
      .status(400)
      .json({ message: "Folder name cannot contain the '@' symbol" });
  }

  try {
    const folderNameWithUserId = `${folderName}@${userId}`;
    const newFolder = new Folder({
      name: folderNameWithUserId,
      userId,
    });
    await newFolder.save();

    const userFolders = await Folder.find({ userId }).select("name");

    const folderNames = userFolders.map((folder) => folder.name.split("@")[0]);

    res.status(201).json(folderNames);
  } catch (error) {
    console.error(
      "Error creating folder or retrieving folders:",
      error.message
    );

    res.status(500).json({
      error: "An unexpected error occurred while processing the request.",
    });
  }
};

const deleteFolder = async (req, res) => {
  const { folderName } = req.body;
  const { id } = req.params;
  console.log("folderName:", folderName);

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    const formattedFolderName = `${folderName}@${userId}`;

    const deletedFolder = await Folder.findOneAndDelete({
      name: formattedFolderName,
      userId,
    });

    if (!deletedFolder) {
      return res.status(404).json({ error: "Folder not found." });
    }

    const formsToDelete = await Form.find({
      folderName: formattedFolderName,
      userId,
    });

    const formNamesToDelete = formsToDelete.map((form) => form.formName);

    await Form.deleteMany({
      folderName: formattedFolderName,
      userId,
    });

    await Response.deleteMany({
      folderName: formattedFolderName,
      userId,
      formName: { $in: formNamesToDelete },
    });

    await Analytics.deleteMany({
      folderName: formattedFolderName,
      userId,
      formName: { $in: formNamesToDelete },
    });

    const formsByFolder = await Form.find({ userId }).select(
      "formName folderName -_id"
    );

    const folderForms = {};
    formsByFolder.forEach((form) => {
      const originalFolderName = form.folderName.split("@")[0];
      if (!folderForms[originalFolderName]) {
        folderForms[originalFolderName] = [];
      }
      folderForms[originalFolderName].push(form.formName.split("@")[0]);
    });

    const folders = await Folder.find({ userId }).select("name -_id");
    const folderNames = folders.map((folder) => folder.name.split("@")[0]);

    folderNames.forEach((originalFolderName) => {
      if (!folderForms[originalFolderName]) {
        folderForms[originalFolderName] = [];
      }
    });
    console.log(folderForms);
    res.status(200).json({
      folders: folderNames,
      folderForms,
    });
  } catch (error) {
    console.error(
      "Error deleting folder or retrieving folders:",
      error.message
    );

    res.status(500).json({
      error: "An unexpected error occurred while processing the request.",
    });
  }
};

const createForm = async (req, res) => {
  try {
    const { formName, folderName } = req.body;
    const { id } = req.params;

    const userId = mongoose.Types.ObjectId.isValid(id)
      ? new mongoose.Types.ObjectId(id)
      : null;

    if (!userId) {
      return res.status(400).json({ message: "Invalid userId format" });
    }

    if (!formName || formName.includes("@")) {
      return res.status(400).json({
        message: "Invalid formName. The name must not include '@'.",
      });
    }

    const formattedFormName = `${formName}@${folderName}@${userId}`;
    console.log("formattedFormName", formattedFormName);

    const form = new Form({
      formName: formattedFormName,
      userId,
      folderName: `${folderName}@${userId}`,
    });

    await form.save();

    const formsByFolder = await Form.find({ userId }).select(
      "formName folderName -_id"
    );

    const folderForms = {};
    formsByFolder.forEach((form) => {
      const cleanedFolderName = form.folderName.split("@")[0];

      if (!folderForms[cleanedFolderName]) {
        folderForms[cleanedFolderName] = [];
      }

      const originalFormName = form.formName.split("@")[0];
      folderForms[cleanedFolderName].push(originalFormName);
    });

    const folders = await Folder.find({ userId }).select("name -_id");

    const cleanedFolders = folders.map((f) => f.name.split("@")[0]);

    res.status(200).json({
      folders: cleanedFolders,
      folderForms,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error creating form", error });
  }
};

const deleteForm = async (req, res) => {
  try {
    const { formName, folderName } = req.body;
    const { id } = req.params;

    const userId = mongoose.Types.ObjectId.isValid(id)
      ? new mongoose.Types.ObjectId(id)
      : null;

    if (!userId) {
      return res.status(400).json({ message: "Invalid userId format" });
    }

    const folderExists = await Folder.findOne({
      userId,
      name: `${folderName}@${userId}`,
    });
    if (!folderExists) {
      return res.status(404).json({ error: "Folder not found." });
    }

    const deletedForm = await Form.findOneAndDelete({
      userId,
      folderName: `${folderName}@${userId}`,
      formName: `${formName}@${folderName}@${userId}`,
    });

    if (!deletedForm) {
      return res.status(404).json({ error: "Form not found." });
    }

    await Analytics.deleteMany({
      userId,
      formName: `${formName}@${folderName}@${userId}`,
      folderName: `${folderName}@${userId}`,
    });

    await Response.deleteMany({
      userId,
      formName: `${formName}@${folderName}@${userId}`,
      folderName: `${folderName}@${userId}`,
    });

    const formsByFolder = await Form.find({ userId }).select(
      "formName folderName -_id"
    );

    const folderForms = {};
    formsByFolder.forEach((form) => {
      const cleanedFolderName = form.folderName.split("@")[0];

      if (!folderForms[cleanedFolderName]) {
        folderForms[cleanedFolderName] = [];
      }

      const originalFormName = form.formName.split("@")[0];
      folderForms[cleanedFolderName].push(originalFormName);
    });

    const folders = await Folder.find({ userId }).select("name -_id");
    const cleanedFolderNames = folders.map((f) => f.name.split("@")[0]);

    cleanedFolderNames.forEach((folder) => {
      if (!folderForms[folder]) {
        folderForms[folder] = [];
      }
    });

    res.status(200).json({ folders: cleanedFolderNames, folderForms });
  } catch (error) {
    console.error("Error deleting form or retrieving forms:", error.message);
    res.status(500).json({
      error: "An unexpected error occurred while processing the request.",
    });
  }
};

const updateFormContent = async (req, res) => {
  try {
    console.log("Reaching updateFormContent");

    const { id } = req.params;
    console.log(id);

    const userId = mongoose.Types.ObjectId.isValid(id)
      ? new mongoose.Types.ObjectId(id)
      : null;

    if (!userId) {
      return res.status(400).json({ message: "Invalid userId format" });
    }

    const { formName, folderName, elements, newFormName } = req.body;
    console.log(formName, folderName, elements);

    if (!formName || !folderName) {
      return res
        .status(400)
        .json({ error: "Missing required formName or folderName" });
    }

    const formattedFolderName = `${folderName}@${userId}`;
    const currentFormattedFormName = `${formName}@${folderName}@${userId}`;

    if (newFormName) {
      try {
        const newFormattedFormName = `${newFormName}@${folderName}@${userId}`;

        const existingForm = await Form.findOne({
          formName: currentFormattedFormName,
          userId,
          folderName: formattedFolderName,
        });

        if (!existingForm) {
          return res.status(404).json({ error: "Form not found" });
        }

        existingForm.formName = newFormattedFormName;

        await Analytics.updateMany(
          {
            userId,
            formName: currentFormattedFormName,
            folderName: formattedFolderName,
          },
          { $set: { formName: newFormattedFormName } }
        );

        await Response.updateMany(
          {
            userId,
            formName: currentFormattedFormName,
            folderName: formattedFolderName,
          },
          { $set: { formName: newFormattedFormName } }
        );

        await existingForm.save();
        return res
          .status(200)
          .json({ message: "Form name updated successfully" });
      } catch (error) {
        console.error("Error updating form name:", error);
        return res.status(500).json({ error: "Server error" });
      }
    }

    if (!elements) {
      return res.status(400).json({ error: "Missing required elements field" });
    }

    const existingForm = await Form.findOne({
      formName: currentFormattedFormName,
      userId,
      folderName: formattedFolderName,
    });

    if (!existingForm) {
      return res.status(404).json({ error: "Form not found" });
    }

    existingForm.elements = elements;

    await existingForm.save();

    res.status(200).json({
      message: "Form updated successfully",
      form: existingForm,
    });
  } catch (error) {
    console.error("Error updating form:", error);
    res.status(500).json({ error: "Server error" });
  }
};

const addFormResponses = async (req, res) => {
  const { id } = req.params;
  const { folderName, formName, responses } = req.body;
  console.log("Received responses:", folderName, formName, responses);

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    const formattedFolderName = `${folderName}@${userId}`;

    const formattedFormName = `${formName}@${formattedFolderName}`;

    const form = await Form.findOne({
      formName: formattedFormName,
      userId,
      folderName: formattedFolderName,
    });

    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }

    const latestResponse = await Response.findOne({
      userId,
      folderName: formattedFolderName,
      formName: formattedFormName,
    }).sort({ timestamp: -1 });

    const lastUserValue = latestResponse ? latestResponse.user : 0;
    const newUser = lastUserValue + 1;

    const savedResponses = [];
    for (const resp of responses) {
      const { buttonType, response, order, timestamp } = resp;

      if (!order || !buttonType) {
        return res.status(400).json({
          message: "order and buttonType are required for each response",
        });
      }

      const element = form.elements.find(
        (el) => el.order === order && el.buttonType === buttonType
      );

      if (element) {
        const newResponse = new Response({
          userId,
          folderName: formattedFolderName,
          formName: formattedFormName,
          user: newUser,
          buttonType,
          content: element.content,
          response,
          order,
          timestamp: new Date(timestamp),
        });

        await newResponse.save();
        savedResponses.push(newResponse);
      } else {
        console.log(
          `Element not found for order ${order} and buttonType ${buttonType}`
        );
      }
    }

    res.status(200).json({
      message: "Responses added successfully",
      responses: savedResponses,
    });
  } catch (error) {
    console.error("Error adding responses:", error);
    res.status(500).json({
      message: "Error adding responses",
      error: error.message,
    });
  }
};

const getFormResponses = async (req, res) => {
  const { id } = req.params;
  const { folderName, formName } = req.query;
  console.log("reached", folderName, formName);

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    const formattedFolderName = `${folderName}@${userId}`;

    const formattedFormName = `${formName}@${formattedFolderName}`;

    const responses = await Response.find({
      userId,
      folderName: formattedFolderName,
      formName: formattedFormName,
    });

    console.log("Responses:", responses);

    if (!responses || responses.length === 0) {
      return res.status(404).json({
        message: "No responses found for the given form",
      });
    }

    res.status(200).json({
      message: "Responses fetched successfully",
      folderName,
      formName,
      responses,
    });
  } catch (error) {
    console.error("Error fetching responses:", error);
    res.status(500).json({
      message: "Error fetching responses",
      error: error.message,
    });
  }
};

const getFormContent = async (req, res) => {
  try {
    console.log("Reaching getFormContent");

    const { id } = req.params;
    console.log("UserId:", id);

    const userId = mongoose.Types.ObjectId.isValid(id)
      ? new mongoose.Types.ObjectId(id)
      : null;

    if (!userId) {
      return res.status(400).json({ message: "Invalid userId format" });
    }

    const { formName, folderName } = req.query;
    console.log("formName:", formName, "folderName:", folderName);

    if (!formName || !folderName) {
      return res.status(400).json({ error: "Missing formName or folderName" });
    }

    const formattedFolderName = `${folderName}@${userId}`;
    const formattedFormName = `${formName}@${folderName}@${userId}`;

    const form = await Form.findOne({
      userId,
      formName: formattedFormName,
      folderName: formattedFolderName,
    });

    if (!form) {
      return res.status(404).json({ error: "Form not found" });
    }

    const cleanedFolderName = form.folderName.split("@")[0];

    res.status(200).json({
      formName: form.formName.split("@")[0],
      folderName: cleanedFolderName,
      elements: form.elements,
      responses: form.responses,
    });
  } catch (error) {
    console.error("Error fetching form data:", error);
    res.status(500).json({ error: "Server error" });
  }
};

const updateAnalytics = async (req, res) => {
  const { id } = req.params;
  const { folderName, formName, analytics } = req.body;

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    if (!["view", "start", "completed"].includes(analytics)) {
      return res.status(400).json({ message: "Invalid analytics type" });
    }

    const formattedFolderName = `${folderName}@${userId}`;

    const formattedFormName = `${formName}@${formattedFolderName}`;

    const updateOperation = { $inc: { [analytics]: 1 } };

    const result = await Analytics.findOneAndUpdate(
      {
        userId,
        folderName: formattedFolderName,
        formName: formattedFormName,
      },
      updateOperation,
      { new: true, upsert: true }
    );

    console.log(result);

    res.status(200).json({
      message: "Analytics updated successfully",
      data: {
        folderName: formattedFolderName.split("@")[0],
        formName: formattedFormName.split("@")[0],
        analytics: result,
      },
    });
  } catch (error) {
    console.error("Error updating analytics:", error);
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  }
};

const getAnalytics = async (req, res) => {
  const { id } = req.params;
  const { folderName, formName } = req.query;

  const userId = mongoose.Types.ObjectId.isValid(id)
    ? new mongoose.Types.ObjectId(id)
    : null;

  if (!userId) {
    return res.status(400).json({ message: "Invalid userId format" });
  }

  try {
    const formattedFolderName = `${folderName}@${userId}`;

    const formattedFormName = `${formName}@${formattedFolderName}`;

    const analyticsData = await Analytics.findOne({
      userId,
      folderName: formattedFolderName,
      formName: formattedFormName,
    });

    console.log("analyticsData:", analyticsData);

    if (!analyticsData) {
      return res.status(404).json({ message: "Analytics data not found" });
    }

    res.status(200).json({
      folderName,
      formName,
      view: analyticsData.view || 0,
      start: analyticsData.start || 0,
      completed: analyticsData.completed || 0,
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

module.exports = {
  getUser,
  createFolder,
  deleteFolder,
  createForm,
  deleteForm,
  updateFormContent,
  getFormContent,
  addFormResponses,
  getFormResponses,
  updateAnalytics,
  getAnalytics,
  updateUser,
  addWorkSpaces,
  getWorkSpaces,
};
