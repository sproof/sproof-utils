const utils = require ('ethereumjs-util');
const Transaction = require ('ethereumjs-tx');
const hdkey = require('ethereumjs-wallet/hdkey');
const generateMnemonic = require('bip39').generateMnemonic
const randomBytes = require('crypto').randomBytes;
const ecies = require ('eth-ecies');

let orderedJson = (o) => {
  return Object.keys(o).sort().reduce((r, k) => (r[k] = o[k], r), {});
};


let sha3 = (data) => {
  if (typeof data === 'string') {
    return utils.sha3(data).toString('hex')
  }
  if (Buffer.isBuffer(data))
    return utils.sha3(data).toString('hex');
  if (typeof data === 'object') {
    let dataStr = JSON.stringify(orderedJson(data));
    return utils.sha3(dataStr).toString('hex')
  }
};

let isHash = (data) => {
  let regex = /[0-9A-Fa-f]{6}/g;
  return (data.length === 64 && regex.test(data));
};

let addHexPrefix = (str) => {
  return `0x${str}`;
}

let removeHexPrefix = (data) => {
  if (typeof data === 'string')
    return data.startsWith('0x') ? data.substring(2) : data;
  else return data;
}

let unixTimestamp = () => {
  return Math.round(new Date().getTime()/1000);
}

module.exports = {
  getHash : (data) => {
    return addHexPrefix(sha3(data));
  },

  getSalt : () => {
    return addHexPrefix(sha3(randomBytes(256).toString('hex')));
  },

  publicKeyToAddress : (publicKey) => {
    return addHexPrefix(pubToAddress(publicKey).toString('hex'));
  },

  getCredentials : () => {
    let seed = generateMnemonic();
    let hdWallet = hdkey.fromMasterSeed(seed);
      return {
        key: (hdWallet.privateExtendedKey().toString('hex')),
        address: (hdWallet.deriveChild(0).getWallet().getAddressString()),
        publicKey: (hdWallet.deriveChild(0).getWallet().getPublicKeyString()),
        privateKey: (hdWallet.deriveChild(0).getWallet().getPrivateKeyString()),
        mnemonic: seed
      }
      },

  sign : (message, privateKey) => {
    privateKey = removeHexPrefix(privateKey);
    message = removeHexPrefix(message);

    let key = Buffer.isBuffer(privateKey) ? privateKey : new Buffer(privateKey, 'hex');
    let hash = isHash(message) ? message : sha3(message);
    let signature = utils.ecsign(new Buffer(hash, 'hex'), key);

    return {
      r: addHexPrefix(signature.r.toString('hex')),
      s: addHexPrefix(signature.s.toString('hex')),
      v: Number.parseInt(signature.v)
    };
  },

  verify : (message, signature, publicKeyOrAddress) => {
    message = removeHexPrefix(message);
    publicKeyOrAddress = removeHexPrefix(publicKeyOrAddress);

    let hash = isHash(message) ? message : sha3(message);
    let pub = utils.ecrecover(new Buffer(hash, 'hex'), signature.v, new Buffer(removeHexPrefix(signature.r), 'hex'), new Buffer(removeHexPrefix(signature.s), 'hex'));
    let addrString = utils.pubToAddress(pub).toString('hex');
    let pubString = pub.toString('hex');
    return (pubString === publicKeyOrAddress || addrString === publicKeyOrAddress);
  },

  signTx : (rawTx, privateKey) => {
    privateKey = new Buffer(removeHexPrefix(privateKey), 'hex');
    const tx = new Transaction(rawTx);
    tx.sign(privateKey)
    let txHash = tx.hash();
    return {
      signedTx: addHexPrefix(tx.serialize().toString('hex')),
      transactionHash: addHexPrefix(txHash.toString('hex'))
    }
  },

  isInTimeRange(validFrom, validUntil){
    let currentUnixTimestamp = unixTimestamp();
    validFrom = validFrom ? validFrom : 0;
    validUntil = validUntil ? validUntil : Number.MAX_VALUE;
    return (validFrom < currentUnixTimestamp) && (currentUnixTimestamp < validUntil);
  },

  decrypt(privateKey, encryptedData) {
    privateKey = new Buffer(removeHexPrefix(privateKey), 'hex');
    let bufferEncryptedData = new Buffer(encryptedData, 'base64');

    let decryptedData = ecies.decrypt(privateKey, bufferEncryptedData);

    return JSON.parse(decryptedData.toString('utf8'));
  },

  encrypt(publicKey, data) {
    publicKey = new Buffer(removeHexPrefix(publicKey), 'hex');
    let bufferData = new Buffer(JSON.stringify(data));
    let encryptedData = ecies.encrypt(publicKey, bufferData);
    return encryptedData.toString('base64');
  },

};