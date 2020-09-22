var libsodium = require('libsodium-wrappers-sumo')
const assert = require('assert').strict;
const blake3 = require('blake3')
var FileReader = require('filereader')
var Blob = require('blob');
const derivationCodes = require('../../src/keri/core/derivationCode&Length')
const stringToBnary  = require('../../src/keri/help/stringToBinary')
const {Crymat} = require('../../src/keri/core/cryMat')
const Base64 = require('js-base64').Base64;
async function test_cryderivationcodes(){

assert.equal(derivationCodes.crySelectCodex.two,0)
console.log("assert response ----->",assert.equal(derivationCodes.crySelectCodex.two,0))

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
 * 
 */
async function test_cryMat(){
    await libsodium.ready
    let keypair = await libsodium.crypto_sign_keypair()
let verkey  = 'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
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
let prefix = 'BaU6JR2nmwyZ+i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
 prebin = Buffer.from(prebin, 'binary')


// var cryMat = new Crymat(verkey)
  // let response = cryMat._infil()


//assert.deepStrictEqual(cryMat.raw , verkey) 
//assert.deepStrictEqual(cryMat.code , derivationCodes.oneCharCode.Ed25519N) 
//assert.deepStrictEqual(cryMat._infil(), prefix) 
//assert.deepStrictEqual(Base64.decode(res_infil.toString('utf-8')), prebin.toString()) 


//assert.deepStrictEqual(cryMat.code,derivationCodes.oneCharCode.Ed25519N)
//assert.deepStrictEqual(cryMat.raw,verkey)


// =============================      Testing left for this part  ==================================== 


//comparing crymat.qb2 == decodeB64(crymat.qb64.encode("utf-8"))
//assert crymat.qb64 == encodeB64(crymat.qb2).decode("utf-8")
//console.log("crymat.qb2 =",Base64.decode(res_infil.toString('utf-8')))
// let qb64 = Base64.encode(Base64.decode(res_infil.toString('utf-8'))).toString('utf-8')
// console.log("qb2 ---------------------->",qb64)
// console.log("crymat.qb64 ---------------------->",res_infil)
// console.log("\n decodeB64(crymat.qb64.encode('utf-8') = \n",Base64.encode(Base64.decode(res_infil.toString('utf-8'))).toString('utf-8'))
//assert.deepStrictEqual(Base64.decode(res_infil.toString('utf-8')),Base64.decode(cryMat._infil().toString('utf-8')))
//assert.deepStrictEqual(cryMat._infil(),Base64.encode(Base64.decode(res_infil.toString('utf-8'))).toString('utf-8'))

// ==================================================================================

// cryMat._exfil(prefix)

// assert.deepStrictEqual(cryMat.code,derivationCodes.oneCharCode.Ed25519N)
// console.log("comparing raw code ")
// assert.deepStrictEqual(cryMat.raw,verkey)


// ======================== NEED to correct this test as well ===========================

//  cryMat = new Crymat(null, prefix, null,derivationCodes.oneCharCode.Ed25519N,0)
// assert.deepStrictEqual(cryMat.code,derivationCodes.oneCharCode.Ed25519N)
// assert.deepStrictEqual(cryMat.raw,verkey.toString())


// Testing wrong size of qb64

let longprefix = prefix + "ABCD"
const okcryMat = new Crymat(null, longprefix, null,derivationCodes.oneCharCode.Ed25519N,0)
let res_infil = okcryMat.qb64
console.log("res_infil ------------------->",res_infil.toString())
console.log("okcrymat code ----------------------->",derivationCodes.cryAllSizes[okcryMat.code])
assert.deepStrictEqual(res_infil.length,derivationCodes.cryAllSizes[okcryMat.code])

}


test_cryMat()



// async function stringToBytes(str)
// {
//     let reader = new FileReader();
//     let done = () => {};

//     reader.onload = event =>
//     {
//         done(new Uint8Array(event.target.result), str);
//     };
//     reader.readAsArrayBuffer(new Blob([str], { type: "application/octet-stream" }));

//     return { done: callback => { done = callback; } };
// }