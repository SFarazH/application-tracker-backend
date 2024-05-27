const applicationModel = require("../models/applicationModel");

const addApplication = async (req, res) => {
  const { companyName, jobRole, platform, dateApplied, status } = req.body;
  if (!companyName || !jobRole || !platform || !dateApplied || !status) {
    return res.status(400).json({ message: "Incomplete data sent" });
  }

  try {
    const user = req.user;
    const application = new applicationModel({
      userId: user._id,
      companyName,
      jobRole,
      platform,
      status,
      dateApplied: new Date(dateApplied),
    });

    await application.save();
    return res.status(201).json({ message: "Application added successfully" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const deleteApplication = async (req, res) => {
  const user = req.user;

  try {
    const { applicationId } = req.query;
    console.log(applicationId);
    const application = await applicationModel.findById(applicationId);
    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }
    if (application.userId !== req.user._id.toString()) {
      return res.status(403).json({ message: "Unauthorized" });
    }
    await applicationModel.findByIdAndDelete(applicationId);
    res.status(200).json({ message: "Application deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const updateStatus = async (req, res) => {
  const user = req.user;

  try {
    const { applicationId } = req.query;
    const { status } = req.body;
    console.log(applicationId);
    const application = await applicationModel.findById(applicationId);
    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }
    if (application.userId !== req.user._id.toString()) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    application.status = req.body.status;
    await application.save();

    res.status(200).json({ message: "Application updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = { addApplication, deleteApplication,updateStatus };
