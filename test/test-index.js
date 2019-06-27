var expect    = require('chai').expect;
const utils = require('../src/index');

const account = {
  mnemonic: 'a b c d e f g h i j k l1',
  address: "0x7f3eabdeca6f6410907bf8adf2c4a3ddddefaf54",
  privateKey : '0x21534e62b8fe4daf4c0ddf28f1c941adcb01ed04b723ecdb67925456c690d2a5',
  publicKey : '0x7af08ec04de44c0f8fa9da8f8577229527903c15ae48c9df5f8a175b134e9c8c63b69e226f6c02dbf3d501e2cedd31e30ffc6e73833c2b1e11df03611ef2d344'
};

const rawTx = {
  "nonce": "0x0",
  "gasPrice": "0xb2d05e00",
  "gasLimit": "0x7530",
  "value": "0x0",
  "data": "0x5b575e862ad675bd62f09cff976dcdb08c610a9a95795cae899d1d118480bde98a96b003",
  "chainId": 42
};


describe('hash', () => {
  it('Hash string to sha3 hash', () => {
    var string = 'test';
    var hash = utils.getHash(string);
    expect(hash).to.equal("0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658");
  });
  it('Hash json objects sort differently to sha3 hash and compare if equal', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};
    var json2 = {'test' : 'hallo', b: '2', a: '1'};

    var hash1 = utils.getHash(json1);
    var hash2 = utils.getHash(json2);
    expect(hash1).to.equal(hash2);
  });
  it('Hash different json object should produce different hash', () => {
    var json1 = {'test' : 'hallo', a: '2', b: '2'};
    var json2 = {'test' : 'hallo', b: '2', a: '1'};

    var hash1 = utils.getHash(json1);
    var hash2 = utils.getHash(json2);
    expect(hash1).to.not.equal(hash2);
  });
});

describe('salt', () => {
  it('Get random salt', () => {
    var salt = utils.getSalt();
    expect(salt.length).to.equal(66);
  });
});

describe('sign Tx', () => {
  it('It should create a valid looking signature', () => {
    let signedTx = utils.signTx(rawTx, account.privateKey);
    expect(signedTx.signedTx).to.not.equal(undefined);
    expect(signedTx.transactionHash.length).to.equal(66);
  });
});




describe('sign and verify', () => {
  it('Create a valid signature for data', () => {
    let hash = '0x30f5f50d36a749c9d312f92b5e72d9ee26ad328314bb782c84493cc651aeff77';
    let sig = utils.sign(hash, account.privateKey);
    expect(sig.r).to.have.length(66);
    expect(sig.s).to.have.length(66);
    expect(sig.v).to.be.within(26, 29);
  });

  it('Create a two signatures which should be equal', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};

    let hash = utils.getHash(json1);

    let sigJson = utils.sign(json1, account.privateKey);
    let sigHash = utils.sign(hash, account.privateKey);
    expect(sigJson.r).to.equal(sigHash.r);
    expect(sigJson.s).to.equal(sigHash.s);
    expect(sigJson.v).to.equal(sigHash.v);
  });

  it('Verify crated signature', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};
    let sigJson = utils.sign(json1, account.privateKey);
    let res1 = utils.verify(json1, sigJson, account.publicKey);
    let res2 = utils.verify(json1, sigJson, account.address);
    expect(res1).to.be.true;
    expect(res2).to.be.true;
  });
});

describe('timestamp range', () => {
  it('Get true for valid timerange', () => {
    expect(utils.isInTimeRange(null, null)).to.be.true;
  });
  it('Get false for outdated timerange', () => {
    let validFrom = null;
    let validUntil = 1542721493;
    expect(utils.isInTimeRange(validFrom, validUntil)).to.be.false;
  });


  it('Get false for a timerange in future', () => {
    let current = Math.round(new Date().getTime()/1000);

    expect(utils.isInTimeRange((current+1000), null)).to.be.false;
  });

  it('Get false for a timerange in future', () => {
    let current = Math.round(new Date().getTime()/1000);
    expect(utils.isInTimeRange((current+1000), (current+5000))).to.be.false;
  });

  it('Get true for a valid timerange', () => {
    let current = Math.round(new Date().getTime()/1000);
    expect(utils.isInTimeRange((current-1000), (current+5000))).to.be.true;
  });
});

describe('get credentials', () => {
  it('Get valid credentials', () => {
      let credentials = utils.restoreCredentials(account.mnemonic);
      expect(credentials.address).to.equal(account.address);
      expect(credentials.publicKey).to.equal(account.publicKey);
      expect(credentials.privateKey).to.equal(account.privateKey);
  });

});
