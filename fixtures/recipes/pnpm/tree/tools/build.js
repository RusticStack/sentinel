// A bundler stand-in with content-keyed outputs: one dist file per
// source, named by content hash, so an unchanged input is never
// rewritten — the same invalidation a real bundler cache performs.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

fs.mkdirSync("dist", { recursive: true });
const sources = fs
  .readdirSync("src")
  .filter((f) => f.endsWith(".js"))
  .sort();
for (const f of sources) {
  const body = fs.readFileSync(path.join("src", f));
  const hash = crypto.createHash("sha256").update(body).digest("hex").slice(0, 16);
  const out = path.join("dist", `${f.replace(/\.js$/, "")}.${hash}.js`);
  if (fs.existsSync(out)) {
    console.log(`reused ${f}`);
    continue;
  }
  fs.writeFileSync(out, `// ${f}\n${body}`);
  console.log(`built ${f}`);
}
