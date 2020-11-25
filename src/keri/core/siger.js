const {SigMat} = require('../core/sigmat')



/**
 * Siger is subclass of SigMat, indexed signature material,
    Adds .verfer property which is instance of Verfer that provides
          associated signature verifier.

    See SigMat for inherited attributes and properties:

    Attributes:

    Properties:
        .verfer is Verfer object instance

    Methods:
 */
class Siger extends SigMat {


    constructor(verfer = null , ...args){

        super(...args)
        this._verfer = verfer
    }



    verfer(){
        return this._verfer
    }

    set_verfer(verfer){
this._verfer = verfer
    }
} 

module.exports = {Siger}