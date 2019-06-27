const utils = require ('ethereumjs-util');
const EthereumTx = require ('ethereumjs-tx');
const hdkey = require('ethereumjs-wallet/hdkey');
const generateMnemonic = require('bip39').generateMnemonic;
const mnemonicToSeedSync = require('bip39').mnemonicToSeedSync;

const randomBytes = require('crypto').randomBytes;
const ecies = require ('eth-ecies');

let orderedJson = (o) => {
  return Object.keys(o).sort().reduce((r, k) => (r[k] = o[k], r), {});
};

let sha3 = (data) => {
  if (typeof data === 'string') {
    return utils.keccak(data).toString('hex')
  }
  if (Buffer.isBuffer(data))
    return utils.keccak(data).toString('hex');
  if (typeof data === 'object') {
    let dataStr = JSON.stringify(orderedJson(data));
    return utils.keccak(dataStr).toString('hex')
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


let createCredentials = (mnemonic) => {
  let seed = mnemonicToSeedSync(mnemonic);
  let hdWallet = hdkey.fromMasterSeed(seed);
  let wallet = hdWallet.derivePath("m/44'/60'/0'/0/0").getWallet();

  return {
    address: (wallet.getAddressString()),
    publicKey: (wallet.getPublicKeyString()),
    privateKey: (wallet.getPrivateKeyString()),
    mnemonic: mnemonic
  }
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
    return createCredentials(seed);
  },

  restoreCredentials : (seed) =>  {
    return createCredentials(seed);
  },

  sign : (message, privateKey) => {
    privateKey = removeHexPrefix(privateKey);
    message = removeHexPrefix(message);

    let key = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, 'hex');
    let hash = isHash(message) ? message : sha3(message);
    let signature = utils.ecsign(Buffer.from(hash, 'hex'), key);

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
    let pub = utils.ecrecover(Buffer.from(hash, 'hex'), signature.v, Buffer.from(removeHexPrefix(signature.r), 'hex'), Buffer.from(removeHexPrefix(signature.s), 'hex'));
    let addrString = utils.pubToAddress(pub).toString('hex');
    let pubString = pub.toString('hex');
    return (pubString === publicKeyOrAddress || addrString === publicKeyOrAddress);
  },

  signTx : (rawTx, privateKey) => {
    privateKey = Buffer.from(removeHexPrefix(privateKey), 'hex');

    let common;
    if (rawTx.chainId === 3) common = {chain : 'ropsten', hardfork: 'petersburg'};
    if (rawTx.chainId === 42) common = {chain : 'kovan', hardfork: 'petersburg'};

    const tx = new EthereumTx.Transaction(rawTx, common);

    tx.sign(privateKey);

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
    privateKey = Buffer.from(removeHexPrefix(privateKey), 'hex');
    let bufferEncryptedData = Buffer.from(encryptedData, 'base64');

    let decryptedData = ecies.decrypt(privateKey, bufferEncryptedData);

    return JSON.parse(decryptedData.toString('utf8'));
  },

  encrypt(publicKey, data) {
    publicKey = Buffer.from(removeHexPrefix(publicKey), 'hex');
    let bufferData = Buffer.from(JSON.stringify(data));
    let encryptedData = ecies.encrypt(publicKey, bufferData);
    return encryptedData.toString('base64');
  },

};
