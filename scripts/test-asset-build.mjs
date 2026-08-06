import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cp, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, relative, resolve, sep } from "node:path";
import process from "node:process";

const projectRoot = process.cwd();
const minifier = resolve(projectRoot, "scripts/minify-js.mjs");
const checker = resolve(projectRoot, "scripts/check-assets.mjs");
const allowlist = resolve(projectRoot, "scripts/asset-reference-allowlist.json");
const temporaryRoot = await mkdtemp(resolve(tmpdir(), "whois-assets-"));

async function findFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await findFiles(path)));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

function run(command, args, cwd = projectRoot) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(result.error?.message || result.stderr || result.stdout || `${command} failed`);
  }
  return result.stdout;
}

async function verifyManifest(manifestTarget) {
  const manifestRoot = dirname(manifestTarget);
  const manifest = await readFile(manifestTarget, "utf8");
  const entries = manifest.trimEnd().split("\n");
  assert(entries.length > 0, "Asset manifest is empty");

  for (const entry of entries) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(entry);
    assert(match, `Invalid sha256sum manifest entry: ${entry}`);
    const target = resolve(manifestRoot, match[2]);
    const targetRelative = relative(manifestRoot, target);
    assert(targetRelative !== ".." && !targetRelative.startsWith(`..${sep}`), `Manifest entry escapes its root: ${match[2]}`);
    const digest = createHash("sha256").update(await readFile(target)).digest("hex");
    assert.equal(digest, match[1], `Checksum mismatch for ${match[2]}`);
  }

  if (process.platform !== "win32") {
    run("sha256sum", ["-c", basename(manifestTarget)], manifestRoot);
  }
}

async function build(root) {
  const staticTarget = resolve(root, "static");
  const templateTarget = resolve(root, "templates");
  const manifestTarget = resolve(root, "assets.sha256");

  await cp(resolve(projectRoot, "static"), staticTarget, { recursive: true });
  await cp(resolve(projectRoot, "templates"), templateTarget, { recursive: true });
  process.stdout.write(run(process.execPath, [minifier, staticTarget, templateTarget, manifestTarget]));
  process.stdout.write(run(process.execPath, [checker, staticTarget, templateTarget, allowlist]));
  await verifyManifest(manifestTarget);

  const paths = [
    ...(await findFiles(staticTarget)),
    ...(await findFiles(templateTarget)),
    manifestTarget,
  ].sort();
  const snapshot = new Map();
  for (const path of paths) snapshot.set(relative(root, path).replaceAll("\\", "/"), await readFile(path));
  return snapshot;
}

try {
  const first = await build(resolve(temporaryRoot, "build-a"));
  const second = await build(resolve(temporaryRoot, "build-b"));
  assert.deepEqual([...first.keys()], [...second.keys()], "Independent asset builds produced different file sets");
  for (const [path, contents] of first) {
    assert.deepEqual(contents, second.get(path), `Independent asset builds differ at ${path}`);
  }
  console.log(`Two independent asset builds are byte-for-byte deterministic across ${first.size} packaged files`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
