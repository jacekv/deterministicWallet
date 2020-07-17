const { assert } = require('console');
const crypto = require('crypto');
const secp256k1 = require('secp256k1');

const REGEX_DERIVATION_PATH = /^m(\/[0-9]+['hH]?)*?/;
const HARDENED_INDEX = 0x80000000;
const ENCODING_PREFIX = {
  main: {
    private: 0x0488ADE4,
    public: 0x0488B21E,
  },
  test: {
    private: 0x04358394,
    public: 0x043587CF,
  },
};

/**
 * Takes a public key and returns the fingerprint of it.
 * @param {Buffer} pubkey
 */
function pubkeyToFingerprint(pubkey) {
  const ripemd160 = crypto.createHash('ripemd160');
  const hash = ripemd160.update(crypto.createHash('sha256').update(pubkey).digest()).digest();
  return hash.slice(0, 4);
}

/**
 * Takes a private key and performs elliptic curve operations to get the public key
 * @param {Buffer} privkey - Private key from which the public key is derived
 */
module.exports.privkeyToPubkey = (privkey, compressed = true) => {
  if (compressed) {
    return Buffer.from(secp256k1.publicKeyCreate(privkey, compressed));
  }
  return Buffer.from(secp256k1.publicKeyCreate(privkey, compressed)).slice(1);
};

/**
 * Adding a padding on the left side
 * @param {string} str which is padded
 * @param {string} padString the padding consists off
 * @param {number} length of the overall string
 * @return {string} the left padded string
 */
function lpad(str, padString, length) {
  let result = str;
  while (result.length < length) {
    result = padString + result;
  }
  return result;
}

function InvalidPathException(message) {
  this.message = message;
  this.name = 'InvalidPathException';
}

function ValueException(message) {
  this.message = message;
  this.name = 'ValueException';
}

function BIP32DerivationError(message) {
  this.message = message;
  this.name = 'ValueException';
}

module.exports.InvalidType = (message) => {
  this.message = message;
  this.name = 'InvalidType';
}

/**
 * Takes a string path and derives it into a list.
 * @param {string} path - String path
 * @returns {Array} Returns the path as a list (separator is /)
 * @throws {InvalidPathException} Throws an InvalidPathException if the path is
 * invald.
 */
module.exports.derivPathToList = (path) => {
  if (!REGEX_DERIVATION_PATH.test(path)) {
    throw new InvalidPathException(`The path '${path}' is not valid.`);
  }
  const indexes = path.split('/').slice(1);
  const listPath = [];
  indexes.forEach((item) => {
    // check if the last char of the item is one of the array chars
    if (['\'', 'h', 'H'].includes(item.slice(-1))) {
      listPath.push(parseInt(item.slice(0, -1), 10) + HARDENED_INDEX);
    } else {
      listPath.push(parseInt(item, 10));
    }
  });
  return listPath;
};

/**
 * Serialize an extended private *OR* public key, as spec by bip-0032.
 * @param {Buffer} key - The public or private key to serialize. Note that if this
 * is a public key it MUST be compressed.
 * @param {Number} depth - 0x00 for master nodes, 0x01 for level-1 derived keys, etc..
 * @param {Buffer} parent - The parent pubkey used to derive the fingerprint, or the
 * fingerprint itself None if master.
 * @param {Number} index - The index of the key being serialized. 0x00000000 if master.
 * @param {Buffer} chaincode = The chain code
 * @returns {Buffer} The serialized extended key
 */
module.exports.serializeExtendedKey = (key, depth, parent, index, chaincode, network = 'main') => {
  assert(Buffer.isBuffer(key) === true && Buffer.isBuffer(chaincode) === true);
  assert(typeof depth === 'number' && typeof index === 'number');
  let fingerprint;
  if (parent !== undefined) {
    assert(Buffer.isBuffer(parent) === true);
    if (parent.length === 33) {
      fingerprint = pubkeyToFingerprint(parent);
    } else if (parent.length === 4) {
      fingerprint = parent;
    } else {
      throw new ValueException('Bad parent, a fingerprint or a pubkey is required');
    }
  } else {
    fingerprint = '00000000';
  }
  const buffer = Buffer.allocUnsafe(78);
  const isPrivkey = (key.length === 32);
  buffer.writeUInt32BE(ENCODING_PREFIX[network][(isPrivkey ? 'private' : 'public')], 0);
  buffer.writeUInt8(depth, 4);
  buffer.writeUInt32BE(parseInt(fingerprint.toString('hex'), 16), 5);
  buffer.writeUInt32BE(index, 9);
  chaincode.copy(buffer, 13);
  if (isPrivkey) {
    key = Buffer.concat([Buffer.alloc(1, 0), key]);
  }
  key.copy(buffer, 45);
  return buffer;
};

/**
 * Unserialize an extended private *OR* public key into its components.
 * @param {Buffer} extendedKey - The public or private key to unserialize.
 * @returns {Object} extendedKeyComponents - Object which contains all the components
 * @returns {String} extendedKeyComponents.network
 * @returns {Number} extendedKeyComponents.depth
 * @returns {Buffer} extendedKeyComponents.fingerprint
 * @returns {Number} extendedKeyComponents.index
 * @returns {Buffer} extendedKeyComponents.chaincode
 * @returns {Buffer} extendedKeyComponents.key
 */
module.exports.unserializeExtendedKey = (extendedKey) => {
  assert(Buffer.isBuffer(extendedKey) === true && extendedKey.length === 78);
  const prefix = parseInt(extendedKey.slice(0, 4).toString('hex'), 16);
  let network;
  if (Object.values(ENCODING_PREFIX.main).includes(prefix)) {
    network = 'main';
  } else {
    network = 'test';
  }
  const depth = extendedKey[4];
  const fingerprint = extendedKey.slice(5, 9);
  const index = parseInt(extendedKey.slice(9, 13).toString('hex'), 16);
  const chaincode = extendedKey.slice(13, 45);
  const key = extendedKey.slice(45);
  return {
    network,
    depth,
    fingerprint,
    index,
    chaincode,
    key,
  };
};

/**
 * A.k.a CKDpriv, in bip-0032, but the hardened way
 *
 * @param {Buffer} privkey - The parent's private key, as bytes
 * @param {Buffer} chaincode - The parent's chaincode, as bytes
 * @param {Number} index - The index of the node to derive
 *
 * @returns {Array} Array where the first element the child private key is
 * and the second element the child chaincode is. Both are Buffers
 *
 * @throws BIP32DerivationError in case derivation of the key fails due to
 * mathematical reasons
 */
module.exports.deriveHardenedPrivateChild = (privkey, chaincode, index) => {
  assert(Buffer.isBuffer(privkey) === true && Buffer.isBuffer(chaincode) === true);
  assert(index & HARDENED_INDEX);
  const paddedIndex = lpad(index.toString(16), '0', 8);
  const data = Buffer.concat([
    Buffer.from('00', 'hex'),
    privkey,
    Buffer.from(paddedIndex, 'hex'),
  ]);
  const payload = crypto.createHmac('sha512', chaincode).update(data).digest();
  try {
    return [
      Buffer.from(secp256k1.privateKeyTweakAdd(Buffer.from(privkey), payload.slice(0, 32))),
      payload.slice(32),
    ];
  } catch (err) {
    throw new BIP32DerivationError(`Invalid private key at index ${index}, try the next one!`);
  }
};

/**
 * A.k.a CKDpriv, in bip-0032
 *
 * @param {Buffer} privkey - The parent's private key
 * @param {Buffer} chaincode - The parent's chaincode
 * @param {Number} index - The index of the node to derive
 *
 * @returns {Array} Array where the first element the child private key is
 * and the second element the child chaincode is. Both are Buffers
 *
 * @throws BIP32DerivationError in case derivation of the key fails due to
 * mathematical reasons
 */
module.exports.deriveUnhardenedPrivateChild = (privkey, chaincode, index) => {
  assert(Buffer.isBuffer(privkey) === true && Buffer.isBuffer(chaincode) === true);
  assert(!(index & HARDENED_INDEX));
  const pubkey = this.privkeyToPubkey(privkey);
  const paddedIndex = lpad(index.toString(16), '0', 8);
  const data = Buffer.concat([
    pubkey,
    Buffer.from(paddedIndex.toString('16'), 'hex'),
  ]);
  const payload = crypto.createHmac('sha512', chaincode).update(data).digest();
  try {
    return [
      Buffer.from(secp256k1.privateKeyTweakAdd(Buffer.from(privkey), payload.slice(0, 32))),
      payload.slice(32),
    ];
  } catch (err) {
    throw new BIP32DerivationError(`Invalid private key at index ${index}, try the next one!`);
  }
};

/**
 * A.k.a CKDpub, in bip-0032.
 *
 * @param {Buffer} pubkey - The parent's (compressed) public key
 * @param {Buffer} chaincode - The paren't chaincode
 * @param {Number} index - The index of the node to derive
 *
 * @returns {Array} Array where the first element the child private key is
 * and the second element the child chaincode is. Both are Buffers
 *
 * @throws BIP32DerivationError in case derivation of the key fails due to
 * mathematical reasons
 */
module.exports.derivePublicChild = (pubkey, chaincode, index) => {
  assert(Buffer.isBuffer(pubkey) === true && Buffer.isBuffer(chaincode) === true);
  assert(!(index & HARDENED_INDEX));
  const paddedIndex = lpad(index.toString(16), '0', 8);
  const data = Buffer.concat([
    pubkey,
    Buffer.from(paddedIndex.toString('16'), 'hex'),
  ]);
  const payload = crypto.createHmac('sha512', chaincode).update(data).digest();
  let tmpPub;
  try {
    tmpPub = secp256k1.publicKeyCreate(payload.slice(0, 32));
  } catch (err) {
    throw new BIP32DerivationError(`Invalid private key at index ${index}, try the next one!`);
  }
  // from buffer to uint8array
  const parentPub = new Uint8Array(pubkey.length);
  for (let i = 0; i < pubkey.length; i += 1) parentPub[i] = pubkey[i];
  try {
    return [
      Buffer.from(secp256k1.publicKeyCombine([tmpPub, parentPub])),
      payload.slice(32),
    ];
  } catch (err) {
    throw new BIP32DerivationError(`Invalid public key at index ${index}, try the next one!`);
  }
};

/**
 * Checks if there is any index in the path which is hardened.
 * @param {List} path - Path with all indecies
 *
 * @return Boolean
 */
module.exports.hardenedIndexInPath = (path) => path.some((element) => element & HARDENED_INDEX);
