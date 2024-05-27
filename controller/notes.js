const userModel = require("../models/userModel");
const { v4: uuidv4 } = require("uuid");

const addNote = async (req, res) => {
  const { note } = req.body;
  if (!note) {
    return res.status(400).json({ message: "Incomplete data sent" });
  }
  try {
    const user = req.user;
    user.notes.push({ noteId: uuidv4(), note: note });
    await user.save();
    res.status(200).json({ message: "Note added successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const deleteNote = async (req, res) => {
  const user = req.user;
  try {
    const { noteId } = req.body;
    if (!noteId || noteId.trim() === "") {
      return res.status(400).json({ message: "Invalid Id provided" });
    }
    const result = await userModel.updateOne(
      { _id: user._id },
      { $pull: { notes: { noteId } } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "Note not found" });
    }
    res.status(200).json({ message: "Note removed successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = { addNote, deleteNote };
