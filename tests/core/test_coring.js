var libsodium = require('libsodium-wrappers-sumo')
var Base64 = require('urlsafe-base64');
const assert = require('assert').strict;
var blake3 = require('blake3')
const utils = require('../../src/keri/core/utls')
const derivationCodes = require('../../src/keri/core/derivationCode&Length')
const stringToBnary = require('../../src/keri/help/stringToBinary')
const { Crymat } = require('../../src/keri/core/cryMat');
const { CryCounter } = require('../../src/keri/core/cryCounter')
const { Verfer } = require('../../src/keri/core/verfer');
const { Diger } = require('../../src/keri/core/diger');
const { Prefixer } = require('../../src/keri/core/prefixer')
const { Nexter } = require('../../src/keri/core/nexter')
const { SigMat } = require('../../src/keri/core/sigmat');
const {Serder}  = require('../../src/keri/core/serder')
const { versify, Serials, Versionage, Ilks, Vstrings } = require('../../src/keri/core/core')
const { Base } = require('msgpack5');
const { copySync } = require('fs-extra');
const util = require('util');
const { serialize } = require('v8');




async function test_cryderivationcodes() {

  assert.equal(derivationCodes.crySelectCodex.two, 0)
  console.log("assert response ----->", assert.equal(derivationCodes.crySelectCodex.two, 0))

  let crySelectCodex = JSON.stringify(derivationCodes.crySelectCodex)
  crySelectCodex.includes('A') == false
  crySelectCodex.includes('0') == true

  assert.equal(derivationCodes.oneCharCode.Ed25519_Seed == 'A')
  assert.equal(derivationCodes.oneCharCode.Ed25519N == 'B')
  assert.equal(derivationCodes.oneCharCode.X25519 == 'C')
  assert.equal(derivationCodes.oneCharCode.Ed25519 == 'D')

  assert.equal(derivationCodes.oneCharCode.Blake3_256 == 'E')
  assert.equal(derivationCodes.oneCharCode.Blake2b_256 == 'F')
  assert.equal(derivationCodes.oneCharCode.Blake2s_256 == 'G')
  assert.equal(derivationCodes.oneCharCode.SHA3_256 == 'H')

  assert.equal(derivationCodes.oneCharCode.SHA2_256 == 'I')
  assert.equal(derivationCodes.oneCharCode.ECDSA_secp256k1_Seed == 'J')
  assert.equal(derivationCodes.oneCharCode.Ed448_Seed == 'K')
  assert.equal(derivationCodes.oneCharCode.X448 == 'L')

  let oneCharCode = derivationCodes.oneCharCode
  oneCharCode.includes('0') == false


  assert.equal(derivationCodes.twoCharCode.Seed_128 == '0A')
  assert.equal(derivationCodes.twoCharCode.Ed25519 == '0B')
  assert.equal(derivationCodes.twoCharCode.ECDSA_256k1 == '0C')

  let jsonString = JSON.stringify(derivationCodes.twoCharCode)
  jsonString.includes('A') == false

}

/**
 * @description : Test the support functionality for cryptographic material
 * @status partially completed
 */
async function test_cryMat() {
  await libsodium.ready
  let keypair = await libsodium.crypto_sign_keypair()
  let verkey = 'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
  let prebin = '\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1fIS\xf3\x874\xbao\x90\x8c'

  // let bytes = stringToBytes(verkey).done(bytes =>
  //     {
  //         console.log(bytes);  
  //         return bytes
  //     });



  // //    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
  // prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
  // prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
  //           b'IS\xf3\x874\xbao\x90\x8c')
  verkey = Buffer.from(verkey, 'binary')
  let prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
  prebin = Buffer.from(prebin, 'binary')
  console.log("prebin ------------->", prebin.toString())


  var cryMat = new Crymat(verkey)
  let res_infil = cryMat.qb2()

  assert.deepStrictEqual(cryMat.raw(), verkey)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.qb64(), prefix)
  assert.deepStrictEqual(res_infil, prebin.toString())


  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.raw(), verkey)


  // =============================      Testing left for this part  ==================================== 
  console.log("cryMat.qb64() -------------------_>", (cryMat.qb64()))
  // console.log("Base64.encode(cryMat.qb2()) ------------------>",decodeURIComponent((Base64.encode(cryMat.qb2()))))
  // assert.deepStrictEqual(cryMat.qb64(),decodeURIComponent(Base64.encode(cryMat.qb2())))
  //  assert.deepStrictEqual(cryMat.qb2(),encodeURIComponent(Base64.decode(cryMat.qb64())))


  // ==================================================================================

  // cryMat._exfil(prefix)

  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  console.log("comparing raw code ")
  assert.deepStrictEqual(cryMat.raw(), verkey)




  cryMat = new Crymat(null, prefix, null, derivationCodes.oneCharCode.Ed25519N, 0)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.raw(), verkey)


  // Testing wrong size of qb64

  // let longprefix = prefix + "ABCD"
  // const okcryMat = new Crymat(null, longprefix, null,derivationCodes.oneCharCode.Ed25519N,0)
  //  res_infil = okcryMat.qb64()

  // assert.deepStrictEqual(res_infil.length,derivationCodes.cryAllSizes[okcryMat.code()])


  // with short prefix
  //  shortprefix = prefix[:-4]
  //  with pytest.raises(ValidationError):
  //      okcrymat = CryMat(qb64=shortprefix)

  cryMat = new Crymat(null, null, prebin, derivationCodes.oneCharCode.Ed25519N, 0)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.raw(), verkey)

  cryMat = new Crymat(null, Buffer.from(prefix, 'utf-8'), null, derivationCodes.oneCharCode.Ed25519N, 0)  // test auto convert bytes to str  
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.raw(), verkey)
  assert.deepStrictEqual(cryMat.qb64(), prefix)
  assert.deepStrictEqual(cryMat.qb64b(), encodeURIComponent(prefix))


  //------------------------------- # test prefix on full identifier --------------------------------

  let full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
  cryMat = new Crymat(null, Buffer.from(full, 'utf-8'))
  assert.deepStrictEqual(cryMat.code(), derivationCodes.oneCharCode.Ed25519N)
  assert.deepStrictEqual(cryMat.raw(), verkey)
  assert.deepStrictEqual(cryMat.qb64(), prefix)

  assert.deepStrictEqual(cryMat.qb2(), prebin.toString())


  // ----------------- Signature tests   Need to fix--------------------------------------

  let sig = '\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e\'m\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t'


  sig = Buffer.from(sig, 'binary')
  // let sig64  =  Base64.encode(sig)
  // console.log("sig64 ------_____>",sig64.toString()) 
  // assert.deepStrictEqual(sig64,'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ==')

  //      ===============================================
  let qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
  let qbin = '\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90'
  qbin = Buffer.from(qbin, 'binary')
  cryMat = new Crymat(sig, null, null, code = derivationCodes.twoCharCode.Ed25519, 0)
  assert.deepStrictEqual(cryMat.raw(), sig)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519)
  assert.deepStrictEqual(cryMat.qb64(), qsig64)
  assert.deepStrictEqual(cryMat.qb2(), decodeURIComponent(qbin))


  cryMat = new Crymat(null, qsig64, null, derivationCodes.oneCharCode.Ed25519N, 0)

  assert.deepStrictEqual(cryMat.raw(), sig)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519)


  cryMat = new Crymat(null, null, qbin, code = derivationCodes.twoCharCode.Ed25519, 0)
  assert.deepStrictEqual(cryMat.raw(), sig)
  assert.deepStrictEqual(cryMat.code(), derivationCodes.twoCharCode.Ed25519)

}



/**
 * @description Subclass of crymat 
 * @status Pending , need to resolve issue with Mahendra
 */
async function test_crycounter() {

  let qsc = derivationCodes.CryCntCodex.Base64 + stringToBnary.intToB64(1, l = 2)
  assert.equal(qsc, '-AAB')

  let qscb = encodeURIComponent(qsc)
  let counter = new CryCounter()

  // assert.deepStrictEqual(counter.raw() , Buffer.from('','binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,1)
  // assert.deepStrictEqual(counter.count() ,1)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter.qb2() ,'binary')).toString() ,encodeURIComponent('-AAB'))

  //  counter = new CryCounter(Buffer.from('','binary'))
  //  assert.deepStrictEqual(counter.raw() , Buffer.from('','binary'))
  //  assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  //  assert.deepStrictEqual(counter.index() ,1)
  //  assert.deepStrictEqual(counter.count() ,1)
  //  assert.deepStrictEqual(counter.qb64() ,qsc)
  //  assert.deepStrictEqual((Buffer.from(counter.qb2() ,'binary')).toString() ,'-AAB')


  //  counter = new CryCounter(null,null, qsc, null)
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,1)
  // assert.deepStrictEqual(counter.count() ,1)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')


  // counter = new CryCounter(null,null, qscb, null)
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,1)
  // assert.deepStrictEqual(counter.count() ,1)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')

  // counter = new CryCounter(Buffer.from('','binary'),null, null, null,derivationCodes.CryCntCodex.Base64,null,1)
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,1)
  // assert.deepStrictEqual(counter.count() ,1)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')


  // counter = new CryCounter(Buffer.from('','binary'),null, null, null,derivationCodes.CryCntCodex.Base64,null,0)
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,0)
  // assert.deepStrictEqual(counter.count() ,0)
  // assert.deepStrictEqual(counter.qb64() ,'-AAA')
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')



  let cnt = 5
  qsc = derivationCodes.CryCntCodex.Base64 + stringToBnary.intToB64(cnt, l = 2)

  // counter = new CryCounter(null,null, null, null,derivationCodes.CryCntCodex.Base64,null,cnt)
  // assert.equal(qsc, '-AAF')
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,cnt)
  // assert.deepStrictEqual(counter.count() ,cnt)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')


  // counter = new CryCounter(null,null, qsc, null)
  // // assert.equal(qsc, '-AAF')
  // assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  // assert.deepStrictEqual(counter.code() ,derivationCodes.CryCntCodex.Base64)
  // assert.deepStrictEqual(counter.index() ,cnt)
  // assert.deepStrictEqual(counter.count() ,cnt)
  // assert.deepStrictEqual(counter.qb64() ,qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')




  qsc = derivationCodes.CryCntCodex.Base2 + stringToBnary.intToB64(cnt, l = 2)

  counter = new CryCounter(null, null, null, null, derivationCodes.CryCntCodex.Base2, null, cnt)
  assert.equal(qsc, '-BAF')
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base2)
  assert.deepStrictEqual(counter.index(), cnt)
  assert.deepStrictEqual(counter.count(), cnt)
  assert.deepStrictEqual(counter.qb64(), qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')


  counter = new CryCounter(null, null, qsc, null)
  // assert.equal(qsc, '-AAF')
  assert.deepStrictEqual(counter.raw(), Buffer.from('', 'binary'))
  assert.deepStrictEqual(counter.code(), derivationCodes.CryCntCodex.Base2)
  assert.deepStrictEqual(counter.index(), cnt)
  assert.deepStrictEqual(counter.count(), cnt)
  assert.deepStrictEqual(counter.qb64(), qsc)
  // assert.deepStrictEqual((Buffer.from(counter._qb2() ,'binary')).toString() ,'-AAB')
}


/**
 * @status completed
 */
async function test_diger() {
  //Create something to digest and verify 
  let ser = Buffer.from("abcdefghijklmnopqrstuvwxyz0123456789", 'binary')
  const hasher = blake3.createHash();
  let dig = blake3.hash(ser);
  let digest = hasher.update(ser).digest('')


  let diger = new Diger(digest)
  assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256)
  assert.deepStrictEqual((diger.raw()).length, derivationCodes.CryOneRawSizes[diger.code()])
  let result = diger.verify(ser)
  assert.equal(result, true)

  result = diger.verify(Buffer.concat([ser, Buffer.from("2j2idjpwjfepjtgi", 'binary')]))
  assert.equal(result, false)
  diger = new Diger(digest, null, derivationCodes.oneCharCode.Blake3_256)
  assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256)
  assert.deepStrictEqual((diger.raw()).length, derivationCodes.CryOneRawSizes[diger._code])
  result = diger.verify(ser)
  assert.equal(result, true)


  diger = new Diger(null, ser)
  assert.deepStrictEqual(diger.code(), derivationCodes.oneCharCode.Blake3_256)
  assert.deepStrictEqual((diger.raw()).length, derivationCodes.CryOneRawSizes[diger.code()])
  result = diger.verify(ser)
  assert.equal(result, true)
}

/**
 * @status pending
 */
async function test_nexter() {

  let verkey = "\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q"
  verkey = Buffer.from(verkey, 'binary')
  let verfer = new Verfer(verkey)

  assert.deepStrictEqual(verfer.qb64(), 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE')

  let sith = '1'.toString(16)     // let hexString =  yourNumber.toString(16);
  let keys = [verfer.qb64()]

  let ser = encodeURIComponent(sith + verfer.qb64())
  //  // (sith + verfer.qb64()).toString('utf-8')
  //   console.log("ser =", ser)
  //  let nexter =  new Nexter(ser) // # defaults provide Blake3_256 digester
  //   assert.deepStrictEqual(nexter.code() , derivationCodes.oneCharCode.Blake3_256) 
  //    assert.deepStrictEqual(nexter.qb64() , 'EEV6odWqE1wICGXtkKpOjDxPOWSrF4UAENqYT06C0ECU') 
  //    assert.deepStrictEqual(nexter.sith() , null) 
  //    assert.deepStrictEqual(nexter.keys() , null) 
  //    assert.deepStrictEqual((nexter.raw()).length , derivationCodes.CryOneRawSizes[nexter.code()]) 
  //    assert.deepStrictEqual(nexter.verify(ser) , true) 
  //    assert.deepStrictEqual(nexter.verify(ser + Buffer.from('ABCDEF','binary')) , false) 


  //   nexter = new Nexter(null,sith,keys)     // # defaults provide Blake3_256 digester
  //   assert.deepStrictEqual(nexter.code() , derivationCodes.oneCharCode.Blake3_256) 
  //   assert.deepStrictEqual((nexter.raw()).length , derivationCodes.CryOneRawSizes[nexter.code()]) 
  //   assert.deepStrictEqual(nexter.sith() , sith) 
  //   assert.deepStrictEqual(nexter.keys() , keys) 

  //  let derivedResponse = nexter.derive(sith,keys)

  //  assert.deepStrictEqual(encodeURIComponent(derivedResponse.ser) , ser) 
  //  assert.deepStrictEqual(derivedResponse.sith , sith) 
  //  assert.deepStrictEqual(derivedResponse.keys , keys) 

  //  assert.deepStrictEqual(nexter.verify(ser) , true) 
  //  assert.deepStrictEqual(nexter.verify(ser + Buffer.from('ABCDEF','binary')) , false)  
  //   # assert nexter.verify(sith=sith, keys=keys)



  // let nexter = new Nexter(null,null,keys)      //# compute sith from keys
  // assert.deepStrictEqual(nexter.keys() , keys) 
  //  assert.deepStrictEqual(nexter.sith() , sith) 

  // let  nexter =  new Nexter(null,1, keys) // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code() , derivationCodes.oneCharCode.Blake3_256) 
  // assert.deepStrictEqual((nexter.raw()).length , derivationCodes.CryOneRawSizes[nexter.code()]) 
  // assert.deepStrictEqual(nexter.keys() , keys) 
  //  assert.deepStrictEqual(nexter.sith() , sith)
  //  let derivedResponse = nexter.derive(sith,keys)
  //  assert.deepStrictEqual(encodeURIComponent(derivedResponse.ser) , ser) 
  //  assert.deepStrictEqual(derivedResponse.sith , sith) 
  //  assert.deepStrictEqual(derivedResponse.keys , keys) 

  //     assert.deepStrictEqual(nexter.verify(ser) , true) 
  //  assert.deepStrictEqual(nexter.verify(ser + Buffer.from('ABCDEF','binary')) , false) 

  // # assert nexter.verify(sith=1, keys=keys)

  // let  ked = {sith :sith , keys:keys}  //# subsequent event

  // let nexter = new Nexter(null,null,null,ked) // # defaults provide Blake3_256 digester
  // assert.deepStrictEqual(nexter.code() , derivationCodes.oneCharCode.Blake3_256) 
  // assert.deepStrictEqual((nexter.raw()).length , derivationCodes.CryOneRawSizes[nexter.code()]) 
  // assert.deepStrictEqual(nexter.keys() , keys) 
  // assert.deepStrictEqual(nexter.sith() , sith)
  // let derivedResponse = nexter.derive(sith,keys)
  //  assert.deepStrictEqual(encodeURIComponent(derivedResponse.ser) , ser) 
  //  assert.deepStrictEqual(derivedResponse.sith , sith) 
  //  assert.deepStrictEqual(derivedResponse.keys , keys) 
  //    assert.deepStrictEqual(nexter.verify(ser) , true) 
  //  assert.deepStrictEqual(nexter.verify(ser + Buffer.from('ABCDEF','binary')) , false) 

}





/**
 * @description :  Test the support functionality for prefixer subclass of crymat
 */
async function test_prefixer() {
  //raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0

  let verkey = '\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q'
  verkey = Buffer.from(verkey, 'binary')
  // let verfer = new Verfer(verkey)
  // assert.deepStrictEqual(verfer.qb64() ,'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE') 




  // let nxtkey = "\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2\xc4_\xf6\x00"
  // nxtkey = Buffer.from(nxtkey, 'binary')
  // let nxtfer = new Verfer(nxtkey, null, null, code = derivationCodes.oneCharCode.Ed25519)
  // assert.deepStrictEqual(nxtfer.qb64(), 'Dpl-JNEryNVTBgyMGmEym7xqzaOpBOngn2gSIssRf9gA')



  // test creation given raw and code no derivation

  //  let prefixer =  new Prefixer(verkey)



  // assert.deepStrictEqual(prefixer.code() , derivationCodes.oneCharCode.Ed25519N) 
  //  assert.deepStrictEqual((prefixer.raw()).length , derivationCodes.CryOneRawSizes[prefixer.code()])
  // assert.deepStrictEqual((prefixer.qb64()).length , derivationCodes.CryOneSizes[prefixer.code()]) 


  // let ked = {keys:[prefixer.qb64()],nxt:''}
  //   assert.deepEqual(prefixer.verify(ked) , true) 

  // ked = {keys:[prefixer.qb64()],nxt:'ABC'}
  // assert.deepEqual(prefixer.verify(ked) , false)

  //raw = null, code = derivation_code.oneCharCode.Ed25519N, ked = null, seed = null, secret = null, ...kwa
  // prefixer = new Prefixer(verkey, derivationCodes.oneCharCode.Ed25519,null,null,null)  //# defaults provide Ed25519N prefixer
  // assert.deepStrictEqual(prefixer.code() , derivationCodes.oneCharCode.Ed25519) 
  // assert.deepStrictEqual((prefixer.raw()).length , derivationCodes.CryOneRawSizes[prefixer.code()]) 
  // assert.deepStrictEqual((prefixer.qb64()).length , derivationCodes.CryOneSizes[prefixer.code()]) 

  // ked = {keys:[prefixer.qb64()]}
  // assert.deepStrictEqual(prefixer.verify(ked) , true) 

  // //raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0
  // verfer = new Verfer(verkey, null, null, derivationCodes.oneCharCode.Ed25519, 0)
  // prefixer = new Prefixer(verfer.raw())
  // assert.deepStrictEqual( prefixer.code() , derivationCodes.oneCharCode.Ed25519N)
  // assert.deepStrictEqual(prefixer.verify(ked) , false)



  //                                  # # Test basic derivation from ked

  // ked = { keys: [verfer.qb64()], nxt: "" }

  //  // raw = null, code = derivation_code.oneCharCode.Ed25519N, ked = null, seed = null, secret = null, ...kwa
  //  let prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519, ked)
  //   assert.deepStrictEqual(prefixer.qb64(), verfer.qb64())
  //   assert.deepStrictEqual(prefixer.verify(ked), true)



  let verfer = new Verfer(verkey, null, null, derivationCodes.oneCharCode.Ed25519N, 0)
  let ked = { keys: [verfer.qb64()], nxt: "" }
  //  let prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, ked)

  //    assert.deepStrictEqual(prefixer.qb64(), verfer.qb64())
  //   assert.deepStrictEqual(prefixer.verify(ked), true)

  // # # Test digest derivation from inception ked
  ked = { keys: [verfer.qb64()], nxt: "ABCD" }
  let vs = versify(Versionage, Serials.json, 0)
  let sn = 0
  let ilk = Ilks.icp
  let sith = 1
  let prefixer = new Crymat(verkey, null, null, derivationCodes.oneCharCode.Ed25519)
  keys = [prefixer.qb64()]
  let nxt = ""
  let toad = 0
  let wits = []
  let cnfg = []
  console.log("key is --------->", vs)
  ked = {
    vs: vs.toString(),         // version string
    pre: "",                                       //# qb64 prefix
    sn: sn.toString(16),             // # hex string no leading zeros lowercase
    ilk: ilk,
    sith: sith.toString(16),             //# hex string no leading zeros lowercase
    keys: keys,                            //# list of qb64
    nxt: nxt,                              //# hash qual Base64
    toad: toad.toString(16),             //  # hex string no leading zeros lowercase
    wits: wits,                            // # list of qb64 may be empty
    cnfg: cnfg,                           // # list of config ordered mappings may be empty
  }
  //util.pad(size.toString(16), VERRAWSIZE)
  console.log("key is --------->", ked)
  prefixer = new Prefixer(null, derivationCodes.oneCharCode.Blake3_256, ked)

  // assert.deepStrictEqual(prefixer.qb64(), 'EFMo3ix8YSCJn5mVK5TvL5A30V-eOXYKfEsqWRWoA6z4')
  // assert.deepStrictEqual(prefixer.verify(ked), true)



  // ==================> This part left =================>
  // # with pytest.raises(DerivationError):
  // #     prefixer = Prefixer(ked=ked)
  // ====================================================>

  // # # Test digest derivation from inception ked



  // # prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
  // # assert prefixer.qb64 == 'EFMo3ix8YSCJn5mVK5TvL5A30V-eOXYKfEsqWRWoA6z4'
  // # assert prefixer.verify(ked=ked) == True

  // # nexter = Nexter(sith=1, keys=[nxtfer.qb64])
  // # ked = dict(vs=vs,  # version string
  // #            pre="",  # qb64 prefix
  // #            sn="{:x}".format(sn),  # hex string no leading zeros lowercase
  // #            ilk=ilk,
  // #            sith="{:x}".format(sith),  # hex string no leading zeros lowercase
  // #            keys=keys,  # list of qb64
  // #            nxt=nexter.qb64,  # hash qual Base64
  // #            toad="{:x}".format(toad),  # hex string no leading zeros lowercase
  // #            wits=wits,  # list of qb64 may be empty
  // #            cnfg=cnfg,  # list of config ordered mappings may be empty
  // #            )

  // # prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
  // # assert prefixer.qb64 == 'EBv1R8a4iqdMsU7QmL0cRR9saFtAWPwP-yMRO532FxHo'
  // # assert prefixer.verify(ked=ked) == True

  // # perm = []
  // # seal = dict(pre='EkbeB57LYWRYNqg4xarckyfd_LsaH0J350WmOdvMwU_Q',
  // #             sn='2',
  // #             ilk=Ilks.ixn,
  // #             dig='E03rxRmMcP2-I2Gd0sUhlYwjk8KEz5gNGxPwPg-sGJds')

  // # ked = dict(vs=vs,  # version string
  // #            pre="",  # qb64 prefix
  // #            sn="{:x}".format(sn),  # hex string no leading zeros lowercase
  // #            ilk=Ilks.dip,
  // #            sith="{:x}".format(sith),  # hex string no leading zeros lowercase
  // #            keys=keys,  # list of qb64
  // #            nxt=nexter.qb64,  # hash qual Base64
  // #            toad="{:x}".format(toad),  # hex string no leading zeros lowercase
  // #            wits=wits,  # list of qb64 may be empty
  // #            perm=cnfg,  # list of config ordered mappings may be empty
  // #            seal=seal
  // #            )

  // # prefixer = Prefixer(ked=ked, code=CryOneDex.Blake3_256)
  // # assert prefixer.qb64 == 'EzLLOofkapRBf7qbD835qX2ZGZJAOildwZTLfiVTIg04'
  // # assert prefixer.verify(ked=ked) == True

  // # #  Test signature derivation

  // # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
  // # seed = (b'\xdf\x95\xf9\xbcK@s="\xee\x95w\xbf>F&\xbb\x82\x8f)\x95\xb9\xc0\x1eS\x1b{L'
  // #         b't\xcfH\xa6')
  // # signer = Signer(raw=seed)
  // # secret = signer.qb64
  // # assert secret == 'A35X5vEtAcz0i7pV3vz5GJruCjymVucAeUxt7THTPSKY'

  // # vs = Versify(version=Version, kind=Serials.json, size=0)
  // # sn = 0
  // # ilk = Ilks.icp
  // # sith = 1
  // # keys = [signer.verfer.qb64]
  // # nxt = ""
  // # toad = 0
  // # wits = []
  // # cnfg = []

  // # nexter = Nexter(sith=1, keys=[nxtfer.qb64])
  // # ked = dict(vs=vs,  # version string
  // #            pre="",  # qb64 prefix
  // #            sn="{:x}".format(sn),  # hex string no leading zeros lowercase
  // #            ilk=ilk,
  // #            sith="{:x}".format(sith),  # hex string no leading zeros lowercase
  // #            keys=keys,  # list of qb64
  // #            nxt=nexter.qb64,  # hash qual Base64
  // #            toad="{:x}".format(toad),  # hex string no leading zeros lowercase
  // #            wits=wits,  # list of qb64 may be empty
  // #            cnfg=cnfg,  # list of config ordered mappings may be empty
  // #            )

  // # prefixer = Prefixer(ked=ked, code=CryTwoDex.Ed25519, seed=seed)
  // # assert prefixer.qb64 == '0B0uVeeaCtXTAj04_27g5pSKjXouQaC1mHcWswzkL7Jk0XC0yTyNnIvhaXnSxGbzY8WaPv63iAfWhJ81MKACRuAQ'
  // # assert prefixer.verify(ked=ked) == True

  // # prefixer = Prefixer(ked=ked, code=CryTwoDex.Ed25519, secret=secret)
  // # assert prefixer.qb64 == '0B0uVeeaCtXTAj04_27g5pSKjXouQaC1mHcWswzkL7Jk0XC0yTyNnIvhaXnSxGbzY8WaPv63iAfWhJ81MKACRuAQ'
  // # assert prefixer.verify(ked=ked) == True

}

/**
 * @description   Test the support functionality for attached signature cryptographic material
 */
async function test_sigmat() {

  // assert.deepStrictEqual(derivationCodes.SigTwoCodex.Ed25519 , 'A')  // # Ed25519 signature.
  // assert.deepStrictEqual(derivationCodes.SigTwoCodex.ECDSA_256k1 , 'B')  // # ECDSA secp256k1 signature.

  // assert.deepStrictEqual(derivationCodes.SigTwoSizes[derivationCodes.SigTwoCodex.Ed25519] , 88)
  // assert.deepStrictEqual(derivationCodes.SigTwoSizes[derivationCodes.SigTwoCodex.ECDSA_256k1] , 88) 


  //  let cs = stringToBnary.intToB64(0)
  //     console.log('------------------->',cs)
  //  assert.deepStrictEqual(cs , "A") 
  //    let i = stringToBnary.b64ToInt('A')
  //  assert.deepStrictEqual(i,0) 

  // cs = stringToBnary.intToB64(27)
  // assert.deepStrictEqual(cs ,"b") 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 27) 

  // cs = stringToBnary.intToB64(27, l=2)
  // assert.deepStrictEqual(cs , "Ab") 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 27) 

  // cs = stringToBnary.intToB64(80)
  // assert.deepStrictEqual(cs , "BQ") 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 80) 

  // cs = stringToBnary.intToB64(4095)
  // assert.deepStrictEqual(cs ,'__') 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 4095) 

  // cs = stringToBnary.intToB64(4096)
  // assert.deepStrictEqual(cs , 'BAA') 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 4096) 

  // cs = stringToBnary.intToB64(6011)
  // assert.deepStrictEqual(cs , "Bd7") 
  // i = stringToBnary.b64ToInt(cs)
  // assert.deepStrictEqual(i , 6011) 




  // # Test attached signature code (empty raw)
  // let qsc = derivationCodes.SigCntCodex.Base64 + stringToBnary.intToB64(0, l=2)
  //  console.log('qsc---------------->',qsc)
  //  assert.deepStrictEqual( qsc ,'-AAA')
  // let sigmat = new SigMat(Buffer.from('','binary'),null,null, derivationCodes.SigCntCodex.Base64,0)
  //  assert.deepStrictEqual(sigmat.raw() , Buffer.from('','binary')) 
  // assert.deepStrictEqual(sigmat.code() , derivationCodes.SigCntCodex.Base64)
  //  assert.deepStrictEqual( sigmat.index() , 0) 
  //  assert.deepStrictEqual(sigmat.qb64() , qsc) 

  // ------------ NEED to test this again ------------------
  //  console.log("value ooooooooooooooooooooooo",sigmat.qb2())
  //  console.log("value ======================",(Buffer.from('\xf8\x00\x00','binary')).toString())
  //Base64.decode((cryMat._qb2())).toString('utf-8')
  // assert.deepStrictEqual(sigmat.qb2() , (Buffer.from('\xf8\x00\x00','binary')).toString()) 



  // let sigmat =  new SigMat(null,qsc,null,derivationCodes.SigTwoCodex.Ed25519,0)
  // assert.deepStrictEqual(sigmat.raw() , Buffer.from('','binary'))
  //  assert.deepStrictEqual(sigmat.code() , derivationCodes.SigCntCodex.Base64)
  // assert.deepStrictEqual( sigmat.index() , 0) 
  //  assert.deepStrictEqual(sigmat.qb64() , qsc) 
  //  assert.deepStrictEqual(sigmat.qb2() , (Buffer.from('\xf8\x00\x00','binary')).toString()) 

  //  idx = 5
  //   let qsc = derivationCodes.SigCntCodex.Base64 + stringToBnary.intToB64(idx, l=2)
  //  assert.deepStrictEqual( qsc ,'-AAF')
  //   sigmat = new SigMat(Buffer.from('','binary'),null,null, derivationCodes.SigCntCodex.Base64,idx)
  //  assert.deepStrictEqual(sigmat.raw() , Buffer.from('','binary')) 
  //  assert.deepStrictEqual(sigmat.code() , derivationCodes.SigCntCodex.Base64)
  //  assert.deepStrictEqual( sigmat.index() , 5)
  //  assert.deepStrictEqual(sigmat.qb64() , qsc) 
  //  assert.deepStrictEqual(sigmat.qb2() , (Buffer.from('\xf8\x00\x05','binary')).toString()) 


  // =================== Signature testing ====================

  let sig = "\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca" + '\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t'

  sig = Buffer.from(sig, 'binary')
  assert.equal(sig.length, 64)
  let sig64 = Base64.encode(sig)

  console.log("base 64 is ----->", decodeURIComponent(Base64.encode(sig)))
  // assert.deepStrictEqual(sig64, 'mdI8OSQkMJ9r+xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K/H9+1298F4Id1DxvIoEmCQ==')

  let qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
  //  let encoded_data =  Base64.decode(encodeURIComponent(qsig64))
  //  console.log('encoded_data =======================>',encoded_data.length)
  //   assert.equal(qsig64.length, 88)
  //  let qbin = Base64.decode(Buffer.from(qsig64,'binary'))
  //   //  console.log("qbin ------------------------>",qbin.length)
  //    assert.equal((qbin.toString()).length,66)
  // console.log("qbin --------------_>",qbin)

  let qbin = '\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90'

  qbin = Buffer.from(qbin, 'binary')

  // let sigmat = new SigMat(sig)

  // assert.deepStrictEqual(sigmat.raw(), sig)
  //  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  // assert.deepStrictEqual(sigmat.index(), 0)
  //  assert.deepStrictEqual(sigmat.qb64(), qsig64)
  //  assert.deepStrictEqual(sigmat.qb2(), qbin.toString())

  // let sigmat = new SigMat(null,qsig64,null,derivationCodes.SigTwoCodex.Ed25519, 0)
  // assert.deepStrictEqual(sigmat.raw(), sig)
  //  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  // assert.deepStrictEqual(sigmat.index(), 0)


  // # # test wrong size of qb64s 
  // let longqsig64 = qsig64 + "ABCD"
  // console.log("latest length of qsig64 is ----------->",longqsig64.length)
  // let  oksigmat = new SigMat(null,longqsig64,null)
  //  assert.deepStrictEqual((oksigmat._qb64).length , derivationCodes.SigSizes[oksigmat.code()]) 

  // # test auto convert bytes to str


  // let sigmat = new SigMat(null,qb64=encodeURIComponent(qsig64),null) 

  //   assert.deepStrictEqual(sigmat.raw(), sig)
  //  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  // assert.deepStrictEqual(sigmat.index(), 0)
  //  assert.deepStrictEqual(sigmat._qb64, qsig64)
  //  assert.deepStrictEqual(sigmat._qb64, encodeURIComponent(qsig64))


  // let sigmat = new SigMat(null,null,qbin) 

  //   assert.deepStrictEqual(sigmat.raw(), sig)
  //  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  // assert.deepStrictEqual(sigmat.index(), 0)


  let sigmat = new SigMat(sig, null, null, derivationCodes.SigTwoCodex.Ed25519, index = 5)
  assert.deepStrictEqual(sigmat.raw(), sig)
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  assert.deepStrictEqual(sigmat.index(), 5)

  // AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ
  // AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEm

  qsig64 = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
  //  assert.deepStrictEqual(sigmat.qb64(), qsig64)

  qbin = '\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90'
  // #         b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
  // #         b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')
  qbin = Buffer.from(qbin, 'binary')
  // assert.deepStrictEqual(sigmat.qb2(), qbin.toString())

  sigmat = new SigMat(null, qsig64, null)
  assert.deepStrictEqual(sigmat.raw(), sig)
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  assert.deepStrictEqual(sigmat.index(), 5)


  sigmat = new SigMat(null, null, qbin)
  assert.deepStrictEqual(sigmat.raw(), sig)
  assert.deepStrictEqual(sigmat.code(), derivationCodes.SigTwoCodex.Ed25519)
  assert.deepStrictEqual(sigmat.index(), 5)

}


/**
 * @description Test the support functionality for verifier subclass of crymat
 */
async function test_verfer() {
  await libsodium.ready
  let seed = libsodium.randombytes_buf(libsodium.crypto_sign_SEEDBYTES)
  let keypair = libsodium.crypto_sign_seed_keypair(seed)
  // console.log("verkey, sigkey",keypair.privateKey, keypair.publicKey)
  let verkey = keypair.publicKey
  let sigkey = keypair.privateKey
  verkey = String.fromCharCode.apply(null, verkey)
  verkey = Buffer.from(verkey, 'binary')
  // console.log("verkey-------------->",String.fromCharCode.apply(null, verkey))
  // console.log("verkey1-------------->",verkey1)
  // let verfer = new Verfer(Buffer.from(verkey,'binary'),null,null, derivationCodes.oneCharCode.Ed25519N)
  // assert.deepStrictEqual(verfer.raw() , verkey)
  // assert.deepStrictEqual( verfer.code() , derivationCodes.oneCharCode.Ed25519N)

  var encoder = new util.TextEncoder('utf-8');

  let ser = encoder.encode('abcdefghijklmnopqrstuvwxyz0123456789')
  //
  console.log("ser =============>", ser)
  var concatArray = new Uint8Array([])
  let sig = await libsodium.crypto_sign_detached(ser, seed + keypair.privateKey) //# sigkey = seed + verkey

  result = verfer.verify(sig, ser)
  assert.deepStrictEqual(result, true)
}


/**
 * @description  Test the support functionality for Serder key event serialization deserialization
 */
async function test_serder() {


  let e1 = {
    vs: Vstrings.json,
    pre: "ABCDEFG",
    sn: "0001",
    ilk: "rot"
  }
  let Version= Versionage

  let serder = new Serder(null,e1)

  assert.deepStrictEqual(serder._ked , e1)
  assert.deepStrictEqual(serder.set_kind() , Serials.json)
  // assert.deepStrictEqual(serder.version() , Version)
  // assert.deepStrictEqual(serder.version() , Version)
  // assert.deepStrictEqual(serder.dig() , 'EaDVEkrFdx8W0ZZAsfwf9mjxhgBt6PvfCmFPdr7RIcfY')
  // assert.deepStrictEqual(serder.digb() , Buffer.from('EaDVEkrFdx8W0ZZAsfwf9mjxhgBt6PvfCmFPdr7RIcfY','binary'))
  // assert.deepStrictEqual(serder.size() , 66)
  // assert.deepStrictEqual(serder.raw() , Buffer.from('{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}','binary'))


}
// test_verfer()
// test_serder()
// test_nexter()
// test_cryMat()
// test_crycounter()
// tecrycounter()
// test_sigmat()
test_prefixer()
