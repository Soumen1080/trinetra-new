// Positive fixture for the Node crypto detectors (not covered by CBOMkit).
const crypto = require("crypto");

// Expect MD5.
function legacyHash(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

// Expect SHA-256.
function modernHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Expect AES-256-CBC, with the key size parsed out of the transformation.
function encrypt(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Expect RSA key generation.
function keys() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}

module.exports = { legacyHash, modernHash, encrypt, keys };
