var expect    = require('chai').expect;
const utils = require('../src/index');

const account = {
  address: "0xa03cb2e3ec12dfaf8688b876a4143225a0c64d15",
  privateKey : '0xc63f0cf10933d15b5f24a22e247ee8639dae7502655cc032edc9279a2f602fb4',
  publicKey : '0x2ab25035b3d357215c7d7656c9f3fa2d37a25e26dd0c75169dadb5b9292dfed3004b3094c8b4a5ba56e4550d77fabc1cc6d678b38e2ab33dfae96daaae3d0c8e'
};

describe('hash', () => {
  describe('Hash string to sha3 hash', () => {
    var string = 'test';
    var hash = utils.getHash(string);
    expect(hash).to.equal("0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658");
  });
  describe('Hash json objects sort differently to sha3 hash and compare if equal', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};
    var json2 = {'test' : 'hallo', b: '2', a: '1'};

    var hash1 = utils.getHash(json1);
    var hash2 = utils.getHash(json2);
    expect(hash1).to.equal(hash2);
  });
  describe('Hash different json object should produce different hash', () => {
    var json1 = {'test' : 'hallo', a: '2', b: '2'};
    var json2 = {'test' : 'hallo', b: '2', a: '1'};

    var hash1 = utils.getHash(json1);
    var hash2 = utils.getHash(json2);
    expect(hash1).to.not.equal(hash2);
  });
});

describe('salt', () => {
  describe('Get random salt', () => {
    var salt = utils.getSalt();
    expect(salt.length).to.equal(66);
  });
});


describe('sign and verify', () => {
  describe('Create a valid signature for data', () => {
    let hash = '0x30f5f50d36a749c9d312f92b5e72d9ee26ad328314bb782c84493cc651aeff77';
    let sig = utils.sign(hash, account.privateKey);
    expect(sig.r).to.have.length(66);
    expect(sig.s).to.have.length(66);
    expect(sig.v).to.be.within(26, 29);
  });

  describe('Create a two signatures which should be equal', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};

    let hash = utils.getHash(json1);

    let sigJson = utils.sign(json1, account.privateKey);
    let sigHash = utils.sign(hash, account.privateKey);
    expect(sigJson.r).to.equal(sigHash.r);
    expect(sigJson.s).to.equal(sigHash.s);
    expect(sigJson.v).to.equal(sigHash.v);
  });

  describe('Verify crated signature', () => {
    var json1 = {'test' : 'hallo', a: '1', b: '2'};
    let sigJson = utils.sign(json1, account.privateKey);
    let res1 = utils.verify(json1, sigJson, account.publicKey);
    let res2 = utils.verify(json1, sigJson, account.address);
    expect(res1).to.be.true;
    expect(res2).to.be.true;
  });
});

describe('timestamp range', () => {
  describe('Get true for valid timerange', () => {
    expect(utils.isInTimeRange(null, null)).to.be.true;
  });
  describe('Get false for outdated timerange', () => {
    let validFrom = null;
    let validUntil = 1542721493;
    expect(utils.isInTimeRange(validFrom, validUntil)).to.be.false;
  });


  describe('Get false for a timerange in future', () => {
    let current = Math.round(new Date().getTime()/1000);

    expect(utils.isInTimeRange((current+1000), null)).to.be.false;
  });

  describe('Get false for a timerange in future', () => {
    let current = Math.round(new Date().getTime()/1000);
    expect(utils.isInTimeRange((current+1000), (current+5000))).to.be.false;
  });

  describe('Get true for a valid timerange', () => {
    let current = Math.round(new Date().getTime()/1000);
    expect(utils.isInTimeRange((current-1000), (current+5000))).to.be.true;
  });
});

describe('get credentials', () => {
  describe('Get valid credentials', () => {
      //todo write test cases
    });

});
