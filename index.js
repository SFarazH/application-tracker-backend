const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { dbConnect } = require("./models/db");
const authRoutes = require("./routes/authRoutes");
const applicationRoutes = require("./routes/applicationRoutes");
const noteRoutes = require("./routes/noteRoutes");
const resumeRoutes = require("./routes/resumeRoutes");

const app = express();
const PORT = process.env.PORT || 4000;

dbConnect();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

app.use("/auth", authRoutes); // auth routes
app.use("/application", applicationRoutes); // application routes
app.use("/note", noteRoutes); // note routes
app.use("/resume", resumeRoutes); // resume routes

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
