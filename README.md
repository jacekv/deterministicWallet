JavaScript implementation of [Bitcoin BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki): hierarchical deterministic wallets (or "HD Wallets"): wallets which can be shared partially or entirely with different systems, each with or without the ability to spend coins

This wallet is bip44 compatible. You can use the bip44 derivation path to derive 
private and public keys.

# EXAMPLE
```javascript
// the random seed could be taken from bip39
const seedHex = Buffer.from('some random seed', 'hex');
const dw = DeterministicWallet.fromSeed(seedHex);

console.log(dw.getMasterXPriv());
console.log(dw.getMasterXPub());

// deriving ethereum key (60' is ethereum - a full list is https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
const myPrivateChild = dw.getPrivkeyFromPath("m/44'/60'/0'/0/0");
// this one returns a compressed public key
const myPublicChild = dw.getPubKeyFromPath("m/44'/60'/0'/0/0");
// and here a decompressed one
const myPublicChildDecompressed = dw.getPubKeyFromPath("m/44'/60'/0'/0/0", false);

// if you want to get the address, use ethereum-util's publicToAddress function
// for this you need the decompressed public key!
const addr = ethUtil.publicToAddress(myPublicChildDecompressed).toString('hex');
console.log('Addresse', `0x${addr2}`);

```
Since you have the private and public keys, you are able to sign transactions for each and every coin.


# License
MIT