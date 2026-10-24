import express from "express";

const app = express();
app.get("/", (_req, res) => res.send("b05"));
console.log(typeof app.listen);
