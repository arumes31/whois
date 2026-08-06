import { spawnSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import process from "node:process";
import { parse } from "parse5";
import { minify } from "terser";

const staticTarget = resolve(process.argv[2] ?? "static");
const templateTarget = resolve(process.argv[3] ?? "templates");
const allowlistPath = process.argv[4] ? resolve(process.argv[4]) : null;

async function findFiles(directory, suffix) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await findFiles(path, suffix)));
    else if (entry.isFile() && entry.name.endsWith(suffix)) files.push(path);
  }
  return files;
}

async function exists(path) {
  try {
    await readFile(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function staticPath(reference) {
  const relative = reference.slice("/static/".length).replaceAll("/", sep);
  const target = resolve(staticTarget, relative);
  if (target !== staticTarget && !target.startsWith(`${staticTarget}${sep}`)) {
    throw new Error(`Static reference escapes the asset root: ${reference}`);
  }
  return target;
}

const allowlist = allowlistPath
  ? JSON.parse(await readFile(allowlistPath, "utf8"))
  : { missing: [], reason: "" };
const allowedMissing = new Set(allowlist.missing ?? []);
const referenced = new Set();
const failures = [];

const javascript = (await findFiles(staticTarget, ".js")).sort();
for (const file of javascript) {
  const check = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (check.status !== 0) failures.push(`${file}: ${check.stderr.trim() || "syntax check failed"}`);

  const source = await readFile(file, "utf8");
  const imports = source.matchAll(/(?:from\s*|import\s*)["'](\.[^"']+)["']/g);
  for (const match of imports) {
    const target = resolve(dirname(file), match[1]);
    if (!(await exists(target))) failures.push(`${file}: missing module import ${match[1]}`);
  }
}

const templates = (await findFiles(templateTarget, ".html")).sort();
let inlineScripts = 0;
for (const file of templates) {
  const source = await readFile(file, "utf8");
  const document = parse(source, { sourceCodeLocationInfo: true });

  async function inspect(node) {
    if (node.attrs) {
      for (const attribute of node.attrs) {
        if ((attribute.name === "src" || attribute.name === "href") && attribute.value.startsWith("/static/")) {
          referenced.add(attribute.value.split(/[?#]/, 1)[0]);
        }
      }
    }
    if (node.tagName === "script" && node.sourceCodeLocation?.startTag && node.sourceCodeLocation?.endTag) {
      const attributes = new Map(node.attrs.map(attribute => [attribute.name, attribute.value]));
      const type = (attributes.get("type") ?? "").trim().toLowerCase();
      const executable = type === "" || ["text/javascript", "application/javascript", "module"].includes(type);
      if (!attributes.has("src") && executable) {
        const start = node.sourceCodeLocation.startTag.endOffset;
        const end = node.sourceCodeLocation.endTag.startOffset;
        const code = source.slice(start, end);
        if (code.trim()) {
          inlineScripts++;
          try {
            await minify(code, { module: type === "module" });
          } catch (error) {
            failures.push(`${file}: invalid inline JavaScript: ${error.message}`);
          }
        }
      }
    }
    for (const child of node.childNodes ?? []) await inspect(child);
    for (const child of node.content?.childNodes ?? []) await inspect(child);
  }
  await inspect(document);
}

const stylesheets = (await findFiles(staticTarget, ".css")).sort();
for (const file of stylesheets) {
  const source = await readFile(file, "utf8");
  for (const match of source.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)) {
    const reference = match[1].trim().split(/[?#]/, 1)[0];
    if (reference.startsWith("/static/")) referenced.add(reference);
  }
}

const observedAllowed = new Set();
for (const reference of [...referenced].sort()) {
  if (await exists(staticPath(reference))) continue;
  if (allowedMissing.has(reference)) observedAllowed.add(reference);
  else failures.push(`missing static asset: ${reference}`);
}
for (const reference of allowedMissing) {
  if (!observedAllowed.has(reference)) failures.push(`stale missing-asset allowlist entry: ${reference}`);
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Asset contract OK: ${javascript.length} JavaScript files, ${inlineScripts} inline scripts, ${referenced.size} references`);
  if (observedAllowed.size > 0) {
    console.warn(`Allowed known-missing references (${observedAllowed.size}): ${allowlist.reason}`);
  }
}
