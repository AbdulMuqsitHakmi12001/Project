const express = require("express");
const mongoose = require("mongoose");
const app = express();

app.get("/", (req, res) => {
  res.send("Hello worl=sdd");
});

mongoose
  .connect(
    "mongodb+srv://admin:admin@cluster0.xjxwhlk.mongodb.net/Node-API?retryWrites=true&w=majority"
  )
  .then(() => {
    console.log("DB connected");
    app.listen(3000, () => {
      console.log("server started");
    });
  })
  .catch((err) => console.log(err));
