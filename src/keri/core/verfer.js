const { Crymat } = require('./cryMat')
const codeAndLength = require('./derivationCode&Length')
const libsodium = require('libsodium-wrappers-sumo')

/**
 * @description  Verfer :sublclass of crymat,helps to verify signature of serialization
 *  using .raw as verifier key and .code as signature cypher suite
 */
class Verfer extends Crymat {

    constructor(raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0) {
                console.log("INSIDE VERFER CLASS ====================>")
        super(raw , qb64 , qb2, code, index )
        console.log("code coming after verfer class is -------->",this._code)
        if (Object.values(codeAndLength.oneCharCode.Ed25519N).includes(this._code) ||
            Object.values(codeAndLength.oneCharCode.Ed25519).includes(this._code)) {

            this._verify = this._ed25519
            console.log("INSIDE VERFER CLASS : this._verify is --------->",this._verify)
        } else {
            throw `Unsupported code = ${this._code} for verifier.`
        }

    }


    /**
     * 
     * @param {bytes} sig   bytes signature  
     * @param {bytes} ser   bytes serialization  
     */
    verify(sig, ser) {

        console.log("LENGTHS are ==============>",sig.length,ser.length,(this._raw).length)
        return this._verify(sig,ser,this._raw)
    }

    /**
     * @description This method will verify ed25519 signature on Serialization using  public key 
     * @param {bytes} sig  
     * @param {bytes} ser 
     * @param {bytes} key 
     */


    _ed25519(sig, ser, key) {

        try {
            let result = libsodium.crypto_sign_verify_detached(sig, ser, key)
            if (result)
                return true
            else
                return false
        } catch (error) {
            throw error
        }

    }
}



module.exports = {Verfer}