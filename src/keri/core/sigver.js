const { Crymat } = require('./cryMat')
const verfer = require('./verfer')
const { Verfer } = require('./verfer')
const derivation_code = require('./derivationCode&Length')



/**
 * @description  A Crymat subclass holding signature with verfer property
 * Verfer verify signature of serialization
 * .raw is signature and .code is signature cipher suite
 * .verfer property to hold Verfer instance of associated verifier public key
 */
class Sigver extends Crymat {

  constructor(raw=null, code=derivation_code.twoCharCode.Ed25519, verfer=null,index = 0) {
// Assign verfer to .verfer attribute
        super(raw ,null,null,code,index)
        this._verfer = verfer
    }


 /**
  * @description  this will return verfer instance 
  */   
     getVerfer(){
        return this._verfer
    }

    setVerfer(verfer){
        this._verfer = verfer
    }
}


module.exports = { Sigver }