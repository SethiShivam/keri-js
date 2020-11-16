const { Crymat } = require("./cryMat");
const derivation_code = require('./derivationCode&Length')
const libsodium = require('libsodium-wrappers-sumo');
const { Verfer } = require("./verfer");
const { decodeAllSync } = require("cbor");
const {Sigver} = require("./sigver");
const {range}  = require('./utls')
/**
 * @description Signer is CryMat subclass with method to create signature of serialization
 * It will use .raw as signing (private) key seed
 * .code as cipher suite for signing and new property .verfer whose property
 *  .raw is public key for signing.
 *  If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.
 */
class Signer extends Crymat {

    constructor(raw = Buffer.from('', 'utf-8'), code = derivation_code.oneCharCode.Ed25519_Seed, transferable = true) {
        let verfer,seedKeypair,verkey,sigkey = null
        try {
            super(raw,null,null,code)
        } catch (error) {
            if (code = derivation_code.oneCharCode.Ed25519_Seed) {
                raw = libsodium.randombytes_buf(libsodium.crypto_sign_SEEDBYTES)
                super(raw,null,null,code)
            } else
                throw `Unsupported signer code = ${code}.`

        }
        if(code == derivation_code.oneCharCode.Ed25519_Seed){
            this._sign = this._ed25519
             seedKeypair = libsodium.crypto_sign_seed_keypair(raw)
             verkey = seedKeypair.publicKey
             sigkey = seedKeypair.privateKey
             if(transferable){
                verfer = new Verfer(raw,null,null,derivation_code.oneCharCode.Ed25519)
             }else{
                verfer = new Verfer(raw,null,null,derivation_code.oneCharCode.Ed25519N)
             }
             
        }else {
            throw `Unsupported signer code = ${code}.`
        }
            this._verfer = verfer
    }


/**
 * @description Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
 */
    verfer(){
         return this.verfer
    }



/**
 * @description Returns either Sigver or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

         If index is None
            return Sigver instance
        Else
            return Siger instance

             ser is bytes serialization
            index is int index of associated verifier key in event keys
 * @param {*} ser 
 * @param {*} index 
 */
    sign(ser, index=null){

        return this._sign(ser,this.raw,this.verfer,index)
    }



    /**
     * @description Returns signature
     * @param {*} ser ser is bytes serialization
     * @param {*} seed seed is bytes seed (private key)
     * @param {*} verfer verfer is Verfer instance. verfer.raw is public key
     * @param {*} index index is index of offset into signers list or None
     */
  async   _ed25519(ser, seed, verfer, index){

    await libsodium.ready

      let  sig = libsodium.crypto_sign_detached(ser, seed + verfer.raw())
      if(!index){
          return  new Sigver(raw=sig, code=CryTwoDex.Ed25519, verfer=verfer)
      }
      else {
        return new Sigver(raw=sig,code=SigTwoDex.Ed25519,verfer=verfer,index=index)
      }
    }




}


    /**
     * @description Returns list of Signers for Ed25519
     * @param {*} root          root is bytes 16 byte long root key (salt/seed) from which seeds for Signers
                                in list are derived
                                 random root created if not provided
     * @param {*} count          count is number of signers in list
     * @param {*} transferable transferable is boolean true means signer.verfer code is transferable
                                non-transferable otherwise
     */
  async function  generateSigners(root=null, count=8, transferable=true){
        await libsodium.ready
            if(!root){
                root = libsodium.randombytes_buf(libsodium.crypto_pwhash_SALTBYTES)
            }
            let signers = []
            let [path,seed] = null
            for(let i in range(count)){
                path = i.toString(16)
                seed = libsodium.crypto_pwhash(32,path,root,libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    alg=libsodium.crypto_pwhash_ALG_DEFAULT)

                    signers.push(new Signer(seed))

            }
            return signers
    }


    /**
     * @description  Returns list of fully qualified Base64 secret seeds for Ed25519 private keys
     * @param {*} root root is bytes 16 byte long root key (salt/seed) from which seeds for Signers
            in list are derived
            random root created if not provided
     * @param {*} count count is number of signers in list
     */
    function generateSecrets(root=null, count=8){

        let signrs =  []
        let signers = generateSigners(root=root, count=count)

        for (let signer in signers){
            signrs.push[signer.qb64()]
        }

        return signrs
    }


module.exports = { Signer ,generateSigners,generateSecrets}