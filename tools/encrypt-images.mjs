/**
 * Encrypt PNG assets for client-side decryption in index.html.
 * Must use the same ASSET_KEY string as in index.html (PBKDF2 + AES-256-GCM).
 *
 * Usage (from project root):
 *   node tools/encrypt-images.mjs
 *
 * Reads: ../sadia.png, ../tonmoy.png
 * Writes: ../sadia.enc, ../tonmoy.enc
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

/** Sync exactly with ASSET_KEY in index.html */
const ASSET_KEY =
  "NrU0QOYePGMBhlMIFwFIqgCLNhhOMtdDOQWR8Erz_jmMVXT5PH1wFw";

const MAGIC = Buffer.from("ENC1");
const PBKDF2_ITERS = 100000;

function encryptBuffer(plain, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERS, 32, "sha256");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, salt, iv, enc, tag]);
}

function main() {
  const pairs = [
    ["sadia.png", "sadia.enc"],
    ["tonmoy.png", "tonmoy.enc"],
  ];
  for (const [srcName, outName] of pairs) {
    const src = path.join(ROOT, srcName);
    const out = path.join(ROOT, outName);
    if (!fs.existsSync(src)) {
      console.error("Missing:", src);
      process.exit(1);
    }
    const plain = fs.readFileSync(src);
    const blob = encryptBuffer(plain, ASSET_KEY);
    fs.writeFileSync(out, blob);
    console.log("Wrote", out, "(" + blob.length + " bytes)");
  }
}

main();
