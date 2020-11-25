const {Signer,init_libsodium} = require('../../src/keri/core/signer')
var libsodium = require('libsodium-wrappers-sumo')
const assert = require('assert').strict;
const derivationCodes = require('../../src/keri/core/derivationCode&Length')
let  {TraitCodex} = require('../../src/keri/eventing/TraitCodex')
let  {Kever} = require('../../src/keri/eventing/Kever')
const {Nexter} = require('../../src/keri/core/nexter')
const {Serder} = require('../../src/keri/core/serder')
const {Prefixer} = require('../../src/keri/core/prefixer')
const {SealEvent} = require('../../src/keri/eventing/util')
const { versify, Serials, Versionage, Ilks, Vstrings, Serialage } = require('../../src/keri/core/core');
const { Logger } = require('../../src/keri/db/database');


/**
 * @description Test the support functionality for key event generation functions
 */
async function test_keyeventfuncs(){

    
let seed = '\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93'
    seed = Buffer.from(seed,'binary')
    console.log("Seed is -------->",seed)

    // # Inception: Non-transferable (ephemeral) case
    await libsodium.ready
    let signer0 =  new Signer(seed,derivationCodes.oneCharCode.Ed25519_Seed,false,libsodium)
//    let signer0 =  new  Signer(seed,null,false)  // original signing keypair non transferable
   
//     assert.deepStrictEqual(signer0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
//     console.log("Case successfully tested")
   let ver_ =  signer0.verfer()
//     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)
    let key0 = [ver_.qb64()]
    let Trait_instance = new TraitCodex()

  let serder = Trait_instance.incept(key0)
//   serder.set_raw()
let ked = serder.ked()
  serder.set_ked(ked)
  // console.log("Serder.raw ---------->",(serder.raw()).toString())
 let response = '{"vs":"KERI10JSON0000cf_","pre":"Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM","sn":"0","ilk":"icp","sith":"1","keys":["Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"","toad":"0","wits":[],"cnfg":[]}'
response = Buffer.from(response , 'binary')
  assert.deepStrictEqual(serder.ked()['pre'], 'Bn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM')
  assert.deepStrictEqual(serder.ked()['nxt'], '')
  console.log("Case successfully tested",(serder.raw()).toString())
  
   assert.deepStrictEqual(serder.raw(),response)





  //# # Inception: Transferable Case but abandoned in incept so equivalent
  signer0 =   new Signer(seed,derivationCodes.oneCharCode.Ed25519_Seed,true,libsodium) //# original signing keypair transferable default
  ver_ =  signer0.verfer()
  key0 = [ver_.qb64()]
  Trait_instance = new TraitCodex()

  serder = Trait_instance.incept(key0)
 
//   serder.set_raw()
 ked = serder.ked()
serder.set_ked(ked)
  // assert.deepStrictEqual(signer0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
  // assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519)


  // // assert.deepStrictEqual(serder.ked()['pre'], 'Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM')
  // // assert.deepStrictEqual(serder.ked()['nxt'], '')
  // let response1 = '{"vs":"KERI10JSON0000cf_","pre":"Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM","sn":"0","ilk":"icp","sith":"1","keys":["Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"","toad":"0","wits":[],"cnfg":[]}'
  // response1 = Buffer.from(response1 , 'binary')
  // assert.deepStrictEqual(serder.raw(),response1)











//# # Inception: Transferable not abandoned i.e. next not empty
let seed2 = `\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8`
 seed2 =  Buffer.from(seed2,'binary')
let signer1 = new Signer(seed2,derivationCodes.oneCharCode.Ed25519_Seed,true,libsodium)  // next signing keypair transferable is default


ver_ =  signer1.verfer()
let key1 = [ver_.qb64()]
Trait_instance = new TraitCodex()
let nexter1 = new  Nexter(null,null,key1)       //# dfault sith is 1
let nxt1 = nexter1.qb64()  //# transferable so nxt is not empty

//     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)

   //  keys=keys0, nxt=nxt1
let serder1 = Trait_instance.incept(key1,null,Versionage,Serials.json,null,nxt1)

 ked = serder1.ked()
  serder1.set_ked(ked)
  console.log("Value of pre is -------------->",serder1.ked()['pre'])

//    assert.deepStrictEqual(signer1.code(),derivationCodes.oneCharCode.Ed25519_Seed)
//    assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519)
//    assert.deepStrictEqual(nexter1.sith(),'1') //# default from keys
//    assert.deepStrictEqual(nxt1,'EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA')
// assert.deepStrictEqual(serder1.ked()["pre"],'Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg')
// assert.deepStrictEqual(serder1.ked()["sn"],'0')
// assert.deepStrictEqual(serder1.ked()["ilk"],Ilks.icp)
// assert.deepStrictEqual(serder1.ked()["nxt"],nxt1)


//   let response2 = '{"vs":"KERI10JSON0000fb_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"0","ilk":"icp","sith":"1","keys":["Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg"],"nxt":"EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA","toad":"0","wits":[],"cnfg":[]}'
//   response2 = Buffer.from(response2 , 'binary')
//   assert.deepStrictEqual(serder1.raw(),response2)
//   assert.deepStrictEqual(serder1.dig(),'EQhXAyg_A_8vbkQ6erwK5d9_QdyNdnB8e9fU6xQXeoXA')
// # assert serder0.dig == 





//# # Rotation: Transferable not abandoned i.e. next not empty
//# # seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
let seed3 = `\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa\x1e\xa2y\xf2e\xf9AL\x1aeK\xafj\xa1pB`



seed3 =  Buffer.from(seed3,'binary')
let signer2 = new Signer(seed3,derivationCodes.oneCharCode.Ed25519_Seed,true,libsodium)  // next signing keypair transferable is default


ver_ =  signer2.verfer()
let key2 = [ver_.qb64()]
Trait_instance = new TraitCodex()
let nexter2 = new  Nexter(null,null,key2)       //# dfault sith is 1
let nxt2 = nexter2.qb64()  //# transferable so nxt is not empty
let pre = serder1.ked()["pre"]
let serder2 = Trait_instance.rotate(pre, key1, serder1.dig(),1,Versionage,Serials.json,null,nxt2)
//     assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519N)

   //  keys=keys0, nxt=nxt1
//let serder2 = Trait_instance.incept(key2,null,Versionage,Serials.json,null,nxt2)
//   serder.set_raw()
 ked = serder2.ked()
 serder2.set_ked(ked)


 

 assert.deepStrictEqual(signer2.code(),derivationCodes.oneCharCode.Ed25519_Seed)
 assert.deepStrictEqual(ver_.code(),derivationCodes.oneCharCode.Ed25519)
 assert.deepStrictEqual(nexter2.sith(),'1') //# default from keys
 assert.deepStrictEqual(nxt2,'EnpCDk0g_k6TGr2rr4F279Si5BucM_Yi4xkffB2XDQOE')
assert.deepStrictEqual(serder2.ked()["pre"],'Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg')
assert.deepStrictEqual(serder2.ked()["sn"],'1')
assert.deepStrictEqual(serder2.ked()["ilk"],Ilks.rot)
assert.deepStrictEqual(serder2.ked()["nxt"],nxt2)


let response3 = '{"vs":"KERI10JSON00013c_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"1","ilk":"rot","dig":"EQhXAyg_A_8vbkQ6erwK5d9_QdyNdnB8e9fU6xQXeoXA","sith":"1","keys":["Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg"],"nxt":"EnpCDk0g_k6TGr2rr4F279Si5BucM_Yi4xkffB2XDQOE","toad":"0","cuts":[],"adds":[],"data":null}'
response3 = Buffer.from(response3 , 'binary')
assert.deepStrictEqual(serder2.raw(),response3)
assert.deepStrictEqual(serder2.dig(),'EV8sa4Hb8ItAXOxFyrNIOwSbFQPW02-lljSrlK0mARZ4')



//# # Interaction:
let serder3 = Trait_instance.interact(pre,serder2.dig(),2)

ked = serder3.ked()
serder3.set_ked(ked)

assert.deepStrictEqual(serder3.ked()["pre"] , pre)
assert.deepStrictEqual(serder3.ked()["sn"] , '2')
assert.deepStrictEqual(serder3.ked()["ilk"] , Ilks.ixn)
assert.deepStrictEqual(serder3.ked()["dig"] , serder2.dig())


let response4 = '{"vs":"KERI10JSON0000a3_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","sn":"2","ilk":"ixn","dig":"EV8sa4Hb8ItAXOxFyrNIOwSbFQPW02-lljSrlK0mARZ4","data":[]}'
response4 = Buffer.from(response4 , 'binary')
assert.deepStrictEqual(serder3.raw() , response4)



//# # Receipt
let serder4 = Trait_instance.receipt(pre, 0, serder3.dig())


ked = serder4.ked()
serder4.set_ked(ked)
let response5 = '{"vs":"KERI10JSON000099_","pre":"Dg0J-BJTjzlVReRFmDJNdHr-sUbXWWV6iRfoBNZhZ3eg","ilk":"rct","sn":"0","dig":"EeBYyZMpdNp0vIPjSUdihy9U8GV-mM4ri8873a0hT4Lo"}'
response5 = Buffer.from(response5 , 'binary')

assert.deepStrictEqual(serder4.ked()["pre"] , pre)
assert.deepStrictEqual(serder4.ked()["sn"] , '0')
assert.deepStrictEqual(serder4.ked()["ilk"] , Ilks.rct)
assert.deepStrictEqual(serder4.ked()["dig"] , serder3.dig())
assert.deepStrictEqual(serder4.raw() , response5)



//# # ValReceipt  chit
let  serderA = Trait_instance.incept(key0, derivationCodes.oneCharCode.Blake3_256,Versionage,Serials.json,null,nxt1 )
ked = serderA.ked()
serderA.set_ked(ked)

SealEvent.dig = serderA.dig()
SealEvent.pre = serderA.ked()["pre"]

assert.deepStrictEqual(serderA.ked()["pre"] , 'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI')
assert.deepStrictEqual(SealEvent.pre , serderA.ked()["pre"])

assert.deepStrictEqual(serderA.ked()["pre"] , 'ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI')
assert.deepStrictEqual(SealEvent.dig , serderA.dig())

let response6 = '{"vs":"KERI10JSON0000fb_","pre":"ErxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI","sn":"0","ilk":"icp","sith":"1","keys":["Dn3uop6hDOZYm-rGZ66ogxBtHEcSuU0FSyb0EnYUpfpM"],"nxt":"EluSZyeNzaFHLOFVB8tD1HFsnI6NQ7BxoDe1DNF-xZRA","toad":"0","wits":[],"cnfg":[]}'
response6 = Buffer.from(response6 , 'binary')

assert.deepStrictEqual(serderA.raw() , response6)




let  serder5 = Trait_instance.chit(pre, 2, serder4.dig(), SealEvent)

ked = serder5.ked()
serder5.set_ked(ked)
assert.deepStrictEqual(serder5.ked()["pre"] , pre)
assert.deepStrictEqual(serder5.ked()["ilk"] , Ilks.vrc)
assert.deepStrictEqual(serder5.ked()["sn"] , "2")
assert.deepStrictEqual(serder5.ked()["dig"] , serder4.dig())
assert.deepStrictEqual(serder5.ked()["seal"] , SealEvent)
// # assert 
// # assert serder5.raw == (b'{"vs":"KERI10JSON00010c_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
// #                        b'c","ilk":"vrc","sn":"2","dig":"EEWroCdb9ARV9R35eM-gS4-5BPPvBXRQU_P89qlhET7E"'
// #                        b',"seal":{"pre":"EyqftoqSC_ANDHdx9v4sygNas8Wvy3szYSuTxjT0lvzs","dig":"EBk2aGu'
// #                        b'L5oHsF64QNAeEPEal-JBYJLe5GvXqp3mLMFKw"}}')
}

async function test_kever(){

  // # Transferable case
  // # Setup inception key event dict
  // # create current key
  let lgr =  new Logger()
  await libsodium.ready
  let sith = 1 
  let skp0 = new Signer(Buffer.from('', 'binary'),derivationCodes.oneCharCode.Ed25519_Seed,true,libsodium)
  let _ver = skp0.verfer()
  let keys = [_ver.qb64()]
//   assert.deepStrictEqual(skp0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
//  console.log("test successfully run")
//  assert.deepStrictEqual(_ver.code(),derivationCodes.oneCharCode.Ed25519)


 //# create next key

 let nxtsith = 1  // # one signer
 let skp1 = new Signer(Buffer.from('', 'binary'),derivationCodes.oneCharCode.Ed25519_Seed,true,libsodium)
  _ver = skp1.verfer()
 let nxtkeys = [_ver.qb64()]
//  assert.deepStrictEqual(skp0.code(),derivationCodes.oneCharCode.Ed25519_Seed)
//  assert.deepStrictEqual(_ver.code(),derivationCodes.oneCharCode.Ed25519)




 let nexter = new Nexter(null,nxtsith,nxtkeys,null)
 let nxt = nexter.qb64()  //# transferable so nxt is not empty

let sn = 0     //# inception event so 0
 let toad = 0   //# no witnesses
 let nsigs = 1    //# one attached signature unspecified index
 let vs = versify(Versionage, Serials.json, 0)
 let    ked0 = {
  vs: vs.toString(),         // version string
  pre: "",                                       //# qb64 prefix
  sn: sn.toString(16),             // # hex string no leading zeros lowercase
  ilk: Ilks.icp,
  sith: sith.toString(16),              //# hex string no leading zeros lowercase
  keys: keys,                            //# list of qb64
  nxt: nxt,                              //# hash qual Base64
  toad: toad.toString(16),             //  # hex string no leading zeros lowercase
  wits: [],                            // # list of qb64 may be empty
  cnfg: [],
       // # list of config ordered mappings may be empty
}


      // # Derive AID from ked
      let   aid0 = new Prefixer(null,derivationCodes.oneCharCode.Ed25519,ked0)
         _ver =  skp0.verfer()
      console.log("DERIVED AID qb64 from KED -------------------->",aid0.qb64())

      // assert.deepStrictEqual(aid0.code(),derivationCodes.oneCharCode.Ed25519)
      // assert.deepStrictEqual(aid0.qb64(),_ver.qb64())


     // # update ked with pre
      ked0.pre = aid0.qb64()


     let tser0 =  new Serder(null,ked0)
       tser0.set_ked(ked0)
      console.log("KED SERIALIZED DATA--------------->",tser0.raw())
    //  # sign serialization
    console.log("Signing Serialized KED--------------->")
     let tsig0 = await skp0.sign(tser0.raw(), 0)
      console.log("SIGNED  Serialized KED DATA--------------->",(tser0.raw()).length)
     // # verify signature
    //  console.log("verifying Serialized KED's Signatures --------------->")
     assert.deepStrictEqual(aid0.qb64(),_ver.qb64())
    _ver.verify(tsig0._raw, tser0.raw())

    let kever = new  Kever(tser0, [tsig0],null, lgr)  // # no error
     console.log("KEVER = ------------->",kever)

    
}





test_kever()