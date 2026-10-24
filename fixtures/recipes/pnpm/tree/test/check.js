const fs = require("fs");
const files = fs.readdirSync("dist").filter((f) => f.endsWith(".js"));
if (files.length === 0) {
  console.error("dist is empty");
  process.exit(1);
}
const a = require("k07a");
const b = require("k07b");
console.log("check ok", a.v, b.v, files.length, "bundles");
