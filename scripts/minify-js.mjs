import { readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import process from "node:process";
import { minify } from "terser";

const target = resolve(process.argv[2] ?? "static");
const licenseComment = /(?:^!|@preserve|@license|\blicense\b)/i;

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

const files = (await findJavaScriptFiles(target)).sort();

if (files.length === 0) {
  throw new Error(`No JavaScript files found under ${target}`);
}

let totalBefore = 0;
let totalAfter = 0;

for (const file of files) {
  const source = await readFile(file, "utf8");
  const result = await minify(source, {
    compress: { passes: 2 },
    mangle: true,
    format: { comments: licenseComment },
  });

  if (!result.code) {
    throw new Error(`Terser produced empty output for ${file}`);
  }

  const output = `${result.code}\n`;
  const temporaryFile = `${file}.minify-tmp`;

  try {
    await writeFile(temporaryFile, output, "utf8");
    await rename(temporaryFile, file);
  } finally {
    await rm(temporaryFile, { force: true });
  }

  const before = Buffer.byteLength(source);
  const after = Buffer.byteLength(output);
  totalBefore += before;
  totalAfter += after;

  console.log(
    `${relative(process.cwd(), file)}: ${formatBytes(before)} -> ${formatBytes(after)}`,
  );
}

const saved = totalBefore - totalAfter;
const reduction = ((saved / totalBefore) * 100).toFixed(1);

console.log(
  `Minified ${files.length} JavaScript files: ${formatBytes(totalBefore)} -> ${formatBytes(totalAfter)} (${reduction}% smaller)`,
);
