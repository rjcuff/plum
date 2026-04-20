#!/usr/bin/env node
"use strict";

const { execFileSync, spawnSync } = require("child_process");
const { existsSync, mkdirSync, chmodSync, createWriteStream } = require("fs");
const { join } = require("path");
const { get } = require("https");
const os = require("os");

const REPO = "rjcuff/plum";
const VERSION = require("./package.json").version;
const CACHE_DIR = join(os.homedir(), ".plum", "bin");
const BIN_PATH = join(CACHE_DIR, process.platform === "win32" ? "plum.exe" : "plum");

function platformAsset() {
  const { platform, arch } = process;

  const osMap = { darwin: "macos", linux: "linux", win32: "windows" };
  const archMap = { x64: "x86_64", arm64: "aarch64" };

  const osName = osMap[platform];
  const archName = archMap[arch];

  if (!osName || !archName) {
    fatal(`Unsupported platform: ${platform}/${arch}`);
  }

  const ext = platform === "win32" ? ".exe" : "";
  return `plum-${osName}-${archName}${ext}`;
}

function fatal(msg) {
  process.stderr.write(`\x1b[31mplum: ${msg}\x1b[0m\n`);
  process.exit(1);
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = createWriteStream(dest);
    function fetch(url) {
      get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return fetch(res.headers.location);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${res.statusCode}\n${url}`));
          return;
        }
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
        file.on("error", reject);
      }).on("error", reject);
    }
    fetch(url);
  });
}

async function ensureBinary() {
  if (existsSync(BIN_PATH)) return BIN_PATH;

  const asset = platformAsset();
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;

  process.stderr.write(`\x1b[35mplum\x1b[0m: downloading binary for ${process.platform}/${process.arch}...\n`);
  process.stderr.write(`\x1b[2m${url}\x1b[0m\n`);

  mkdirSync(CACHE_DIR, { recursive: true });

  try {
    await download(url, BIN_PATH);
  } catch (err) {
    fatal(`Failed to download plum binary:\n${err.message}\n\nInstall manually: https://github.com/${REPO}/releases`);
  }

  if (process.platform !== "win32") {
    chmodSync(BIN_PATH, 0o755);
  }

  process.stderr.write(`\x1b[32m✓\x1b[0m plum ready\n\n`);
  return BIN_PATH;
}

ensureBinary().then((bin) => {
  const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  process.exit(result.status ?? 1);
}).catch((err) => {
  fatal(err.message);
});
