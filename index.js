const crypto = require('crypto');
const { assert } = require('console');
const bs58check = require('bs58check');

const HARDENED_OFFSET = 0x80000000;

const {
  derivPathToList,
  serializeExtendedKey,
  unserializeExtendedKey,
  deriveHardenedPrivateChild,
  deriveUnhardenedPrivateChild,
  derivePublicChild,
  privkeyToPubkey,
  hardenedIndexInPath,
  InvalidType,
} = require('./utils');

class DeterministicWallet {
  /**
   * The constructor to create a new deterministic wallet.
   * @param {Buffer} chaincode - The master chaincode, used to derive keys. As bytes.
   * @param {Object} options - Options is an object. The keys it can contain are 
   *                           describes as options.[key].
   * @param {Buffer} options.privkey  - The master private key for this index (default 0).
   *                     Can be None for pubkey-only derivation. As bytes.
   * @param {Buffer} options.pubkey  - The master public key for this index (default 0).
   *                    Can be None if private key is specified.
   *                    Compressed format. As bytes.
   * @param {Buffer} options.fingeprint : If we are instanciated from an xpub/xpriv, we need
   *                                  to remember the parent's pubkey fingerprint to reserialize !
   * @param {number} options.depth: If we are instanciated from an existing extended key, we
   *                                 need this for serialization.
   * @param {number} options.index: If we are instanciated from an existing extended key, we
   *                                 need this for serialization.
   * @param {string} network: Either 'main' or 'test'.
   */
  constructor(chaincode, options = {}, network = 'main') {
    assert(Buffer.isBuffer(chaincode) === true);
    assert(options.privkey !== undefined || options.pubkey !== undefined);
    if (options.privkey !== undefined) {
      assert(Buffer.isBuffer(options.privkey) === true);
    }
    let pubkey;
    if (options.pubkey !== undefined) {
      assert(Buffer.isBuffer(options.pubkey) === true);
      pubkey = options.pubkey;
    } else {
      pubkey = privkeyToPubkey(options.privkey);
    }
    this.masterChaincode = chaincode;
    this.masterPrivkey = options.privkey;
    this.masterPubkey = pubkey;
    this.depth = (options.depth !== undefined && typeof options.depth === 'number' ? options.depth : 0);
    this.index = (options.index !== undefined && typeof options.index === 'number' ? options.index : 0);
    this.fingerprint = (options.fingerprint !== undefined ? options.fingerprint : undefined);
    this.network = network;
  }

  /**
   * Derives a extended private key from a path and returns it in encoded form.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns The encoded extended private key as string
   */
  getXprivFromPath(path) {
    assert(typeof path === 'string');
    const pathList = derivPathToList(path);
    let parentPubkey;
    if (pathList.length === 0) {
      return this.getMasterXPriv();
    }
    if (pathList.length === 1) {
      parentPubkey = this.masterPubkey;
    } else {
      parentPubkey = this.getPubKeyFromPath(pathList.slice(0, -1));
    }
    const result = this.getExtendedPrivkeyFromPath(pathList);
    const extendedKey = serializeExtendedKey(
      result[0],
      this.depth + pathList.length,
      parentPubkey,
      pathList.pop(),
      result[1],
      this.network,
    );
    return bs58check.encode(extendedKey);
  }

  /**
   * Derives a extended public key from a path and returns it in encoded form.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns The encoded extended public key as string
   */
  getXpubFromPath(path) {
    assert(typeof path === 'string');
    const pathList = derivPathToList(path);
    if (pathList.length === 0) {
      return this.getMasterXPub();
    }
    let parentPubkey;
    if (pathList.length === 1) {
      parentPubkey = this.masterPubkey;
    } else {
      parentPubkey = this.getPubKeyFromPath(pathList.slice(0, -1));
    }
    const result = this.getExtendedPubkeyFromPath(pathList);
    const extendedKey = serializeExtendedKey(
      result[0],
      this.depth + pathList.length,
      parentPubkey,
      pathList.pop(),
      result[1],
      this.network,
    );
    return bs58check.encode(extendedKey);
  }

  /**
   * Get a private key from a derivation path.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns Private key as buffer
   */
  getPrivkeyFromPath(path) {
    return this.getExtendedPrivkeyFromPath(path)[0];
  }

  /**
   * Get a pubkey from a derivation path.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns Public key as buffer
   */
  getPubKeyFromPath(path, compressed = true) {
    return this.getExtendedPubkeyFromPath(path, compressed)[0];
  }

  /**
   * Get an extended private key from a derivation path.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns Returns an array, where the first element is the private key and
   * the second element is the chaincode. Both are Buffers.
   */
  getExtendedPrivkeyFromPath(path) {
    let pathList = path;
    if (typeof path === 'string') {
      pathList = derivPathToList(path);
    }
    let chaincode = this.masterChaincode;
    let privkey = this.masterPrivkey;
    pathList.forEach((index) => {
      if (index & HARDENED_OFFSET) {
        [privkey, chaincode] = deriveHardenedPrivateChild(privkey, chaincode, index);
      } else {
        [privkey, chaincode] = deriveUnhardenedPrivateChild(privkey, chaincode, index);
      }
    });
    return [privkey, chaincode];
  }

  /**
   * Get an extended public key from a derivation path.
   * The path should be in the following form: m/N['hH]?
   *
   * @param {string} path - Path the key is derived from
   *
   * @returns Returns an array, where the first element is the public key and
   * the second element is the chaincode. Both are Buffers.
   */
  getExtendedPubkeyFromPath(path, compressed = true) {
    let pathList = path;
    if (typeof path === 'string') {
      pathList = derivPathToList(path);
    }
    let chaincode = this.masterChaincode;
    let key = this.masterPrivkey;
    let pubkey;
    if (hardenedIndexInPath(pathList)) {
      pathList.forEach((index) => {
        if (index & HARDENED_OFFSET) {
          [key, chaincode] = deriveHardenedPrivateChild(key, chaincode, index);
        } else {
          [key, chaincode] = deriveUnhardenedPrivateChild(key, chaincode, index);
        }
      });
      pubkey = privkeyToPubkey(key, compressed);
    } else {
      key = this.masterPubkey;
      pathList.forEach((index) => {
        [key, chaincode] = derivePublicChild(key, chaincode, index);
        pubkey = key;
      });
    }
    return [pubkey, chaincode];
  }

  /**
   * Returns the master extended key base58 encoded.
   *
   * @returns {String} base58 encoded master extended key
   */
  getMasterXPriv() {
    const extendedKey = serializeExtendedKey(
      this.masterPrivkey,
      this.depth,
      this.fingerprint,
      this.index,
      this.masterChaincode,
      this.network,
    );
    return bs58check.encode(extendedKey);
  }

  /**
   * Returns the master extended public key base58 encoded.
   *
   * @returns {String} Base58 encoded master extended public key
   */
  getMasterXPub() {
    const extendedKey = serializeExtendedKey(
      this.masterPubkey,
      this.depth,
      this.fingerprint,
      this.index,
      this.masterChaincode,
      this.network,
    );
    return bs58check.encode(extendedKey);
  }

  /**
   * Generates a deterministic wallet from a seed.
   *
   * @param {Buffer} seed - Random seed from which a deterministic wallet is
   * generated
   *
   * @return {DeterministicWallet} Returns a deterministic wallet
   *
   * @throws InvalidType exception if argument is not a buffer
   */
  static fromSeed(seed) {
    if (!Buffer.isBuffer(seed)) {
      throw new InvalidType('Argument is not a buffer. Buffer is required');
    }
    const digest = crypto.createHmac('sha512', 'Bitcoin seed').update(seed).digest();
    this.masterSecretKey = digest.subarray(0, 32);
    this.chaincode = digest.subarray(32);
    return new DeterministicWallet(this.chaincode, {
      privkey: this.masterSecretKey,
    });
  }

  /**
   * Generates a deterministic wallet from a base58 encoded extended private key.
   *
   * @param {String} xpriv - Base58 encoded private key from which a deterministic
   * wallet is generated
   *
   * @return {DeterministicWallet} Returns a deterministic wallet
   */
  static fromXpriv(xpriv) {
    const extendedKey = bs58check.decode(xpriv);
    const {
      network, depth, fingerprint, index, chaincode, key,
    } = unserializeExtendedKey(extendedKey);
    return new DeterministicWallet(
      chaincode,
      {
        privkey: key.slice(1),
        fingerprint,
        depth,
        index,
      },
      network,
    );
  }

  /**
   * Generates a deterministic wallet from a base58 encoded extended public key.
   *
   * @param {String} xpub - Base58 encoded public key from which a deterministic
   * wallet is generated
   *
   * @return {DeterministicWallet} Returns a deterministic wallet
   */
  static fromXpub(xpub) {
    const extendedKey = bs58check.decode(xpub);
    const {
      network, depth, fingerprint, index, chaincode, key,
    } = unserializeExtendedKey(extendedKey);
    return new DeterministicWallet(
      chaincode,
      {
        pubkey: key,
        fingerprint,
        depth,
        index,
      },
      network,
    );
  }
}
