import { copyFile, mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import process from "node:process";
import { parse } from "parse5";
import { minify } from "terser";

const staticTarget = resolve(process.argv[2] ?? "static");
const templateTarget = resolve(process.argv[3] ?? "templates");
const licenseComment = /(?:^!|@preserve|@license|\blicense\b)/i;

const domPurifySource = resolve("node_modules/dompurify/dist/purify.min.js");
const domPurifyTarget = resolve(staticTarget, "vendor/purify.min.js");
await mkdir(dirname(domPurifyTarget), { recursive: true });
await copyFile(domPurifySource, domPurifyTarget);

async function findJavaScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = resolve(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await findJavaScriptFiles(path)));
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      files.push(path);
    }
  }

  return files;
}

function formatBytes(bytes) {
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

async function writeAtomically(file, output) {
  const temporaryFile = `${file}.minify-tmp`;

  try {
    await writeFile(temporaryFile, output, "utf8");
    await rename(temporaryFile, file);
  } finally {
    await rm(temporaryFile, { force: true });
  }
}

async function minifyJavaScript(source, file) {
  const result = await minify(source, {
    compress: { passes: 2 },
    mangle: true,
    format: { comments: licenseComment },
  });

  if (!result.code) {
    throw new Error(`Terser produced empty output for ${file}`);
  }

  return result.code;
}

async function findTemplateFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = resolve(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await findTemplateFiles(path)));
    } else if (entry.isFile() && entry.name.endsWith(".html")) {
      files.push(path);
    }
  }

  return files;
}

async function minifyInlineScripts(file) {
  const source = await readFile(file, "utf8");
  const document = parse(source, { sourceCodeLocationInfo: true });
  const scripts = [];

  function collectScripts(node) {
    if (node.tagName === "script" && node.sourceCodeLocation?.startTag && node.sourceCodeLocation?.endTag) {
      scripts.push(node);
    }
    for (const child of node.childNodes ?? []) collectScripts(child);
    for (const child of node.content?.childNodes ?? []) collectScripts(child);
  }

  collectScripts(document);

  let output = "";
  let cursor = 0;
  let count = 0;

  for (const script of scripts) {
    const attributes = new Map(script.attrs.map(attribute => [attribute.name, attribute.value]));
    const type = (attributes.get("type") ?? "").trim().toLowerCase();
    const hasSource = attributes.has("src");
    const nonJavaScriptType = type !== "" && !["text/javascript", "application/javascript", "module"].includes(type);
    const start = script.sourceCodeLocation.startTag.endOffset;
    const end = script.sourceCodeLocation.endTag.startOffset;
    const code = source.slice(start, end);

    if (hasSource || nonJavaScriptType || !code.trim()) continue;

    const minified = await minifyJavaScript(code, `${file} inline script ${count + 1}`);
    output += source.slice(cursor, start);
    output += minified;
    cursor = end;
    count++;
  }

  if (count === 0) return null;

  output += source.slice(cursor);
  await writeAtomically(file, output);
  return { before: Buffer.byteLength(source), after: Buffer.byteLength(output), count };
}

const files = (await findJavaScriptFiles(staticTarget)).sort();
const templates = (await findTemplateFiles(templateTarget)).sort();

if (files.length === 0 && templates.length === 0) {
  throw new Error("No JavaScript assets or HTML templates were found");
}

let totalBefore = 0;
let totalAfter = 0;

for (const file of files) {
  const source = await readFile(file, "utf8");
  const output = `${await minifyJavaScript(source, file)}\n`;
  await writeAtomically(file, output);

  const before = Buffer.byteLength(source);
  const after = Buffer.byteLength(output);
  totalBefore += before;
  totalAfter += after;

  console.log(
    `${relative(process.cwd(), file)}: ${formatBytes(before)} -> ${formatBytes(after)}`,
  );
}

let inlineScriptCount = 0;
for (const file of templates) {
  const result = await minifyInlineScripts(file);
  if (!result) continue;

  totalBefore += result.before;
  totalAfter += result.after;
  inlineScriptCount += result.count;
  console.log(
    `${relative(process.cwd(), file)} (${result.count} inline): ${formatBytes(result.before)} -> ${formatBytes(result.after)}`,
  );
}

const saved = totalBefore - totalAfter;
const reduction = ((saved / totalBefore) * 100).toFixed(1);

console.log(
  `Minified ${files.length} JavaScript files and ${inlineScriptCount} first-party inline scripts: ${formatBytes(totalBefore)} -> ${formatBytes(totalAfter)} (${reduction}% smaller)`,
);
