const { Crymat } = require('./cryMat')
const {extractValues} = require('./utls')
const derivation_code = require('./derivationCode&Length')
const libsodium = require('libsodium-wrappers-sumo')
const blake3 = require('blake3')
const { version } = require('utf8')
const { Verfer } = require('./verfer')
const verfer = require('./verfer')
const { Sigver } = require('./sigver')
const {Ilks,IcpLabels,DipLabels} = require('./../core/core')




/**
 * @description Aider is CryMat subclass for autonomic identifier prefix using basic derivation
    from public key
    inherited attributes and properties:
    Attributes:
    Properties:
    Methods:verify():  Verifies derivation of aid
 */


class Prefixer extends Crymat {
//        elements in digest or signature derivation from inception icp
//  IcpLabels ["sith", "keys", "nxt", "toad", "wits", "cnfg"]

//  elements in digest or signature derivation from delegated inception dip
//  DipLabels  ["sith", "keys", "nxt", "toad", "wits", "perm", "seal"]

    /**
     * @description  // This constructor will assign
     *  ._verify to verify derivation of aid  = .qb64
     */
    constructor(raw = null, code = derivation_code.oneCharCode.Ed25519N, ked = null, seed = null, secret = null,qb64=null,qb2 = null) {
        
        var _derive = null
       
        try {
            console.log("INSIDE PREFIXER CLASS :")
            console.log("KED :")
            console.log("Super: (Code,raw)",code,raw,qb64)
             super(raw, qb64, qb2, code, 0)
           //  throw 'Improper initialization need raw or b64 or b2.';
            
        } catch (error) {
            console.log("ERROR is ------->",error)
            if (!(ked || code))
                throw error  // throw error if no ked found 

               
                console.log("INSIDE CATCH ERROR")
                    if (code == derivation_code.oneCharCode.Ed25519N)
                       {  console.log("INSIDE ED25519N")
                           _derive = _DeriveBasicEd25519N} 
                else if (code == derivation_code.oneCharCode.Ed25519)
                        {
                            console.log("INSIDE ED25519")
                            _derive = _DeriveBasicEd25519 }
                else if (code == derivation_code.oneCharCode.Blake3_256)
                       {
                        console.log("INSIDE Blake3_256")
                        _derive = _DeriveDigBlake3_256
                       }
                else if (code == derivation_code.twoCharCode.Ed25519)
                        _derive = _DeriveSigEd25519
                else
                    throw `Unsupported code = ${code} for prefixer.`

                    console.log("KED is ----------------->",ked)
                let  verfer = _derive(ked,seed,secret) // else obtain AID using ked
                console.log('DERIVED RAW AND CODE iS : ================>',verfer)
                super(verfer.raw, null,null, verfer.code,0)
        
        }
       

            console.log("Code is --------------->",this._code)
            if (this._code == derivation_code.oneCharCode.Ed25519N){
                console.log("INSIDE ED25519N---------->")
                this._verify = this._VerifyBasicEd25519N
            }
            
        else if (this._code == derivation_code.oneCharCode.Ed25519){
            console.log("INSIDE Ed25519")
            this._verify = this._VerifyBasicEd25519
        }
            
        else if (this._code == derivation_code.oneCharCode.Blake3_256){
            console.log("INSIDE Blake3_256")
            this._verify = this._VerifyDigBlake3_256
        }
            
        else if (this._code== derivation_code.twoCharCode.Ed25519){
            console.log("INSIDE twoCharCode.Ed25519")
            this._verify = this._VerifySigEd25519
        }
            
        else
            throw `Unsupported code = ${this.code} for prefixer.`
        }




    /**
     * @description   Returns tuple (raw, code) of basic nontransferable 
     * Ed25519 prefix (qb64) as derived from key event dict ke
     * @param {*} ked  ked is inception key event dict
     * @param {*} seed seed is only used for sig derivation it is the secret key/secret
     * @param {*} secret secret or private key 
     */
    derive(ked, seed=null, secret=null) {
        return this._derive(ked = ked, seed = seed, secret = secret)
    }




    /**
     * @description  This function will return TRUE if derivation from iked for .code matches .qb64
     * @param {*} ked inception key event dict
     */
    verify(ked,pre) {
            console.log("Inside Verify Method ********************")
        return this._verify(ked = ked, pre = this.qb64())

    }



    /**
     * @description This will return  True if verified raises exception otherwise
            Verify derivation of fully qualified Base64 pre from inception iked dict
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
    _VerifyBasicEd25519N(ked, pre) {

        let [keys] = null

        try {
            keys = ked["keys"]
            if (keys.length != 1)
                return false
            if (keys[0] != pre)
                return false
            if (ked['nxt'])
                return false
        } catch (e) {
            return false
        }
        return true
    }




    /**
     * @description  Returns True if verified raises exception otherwise
                     Verify derivation of fully qualified Base64 prefix from
                     inception key event dict (ked)
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
    _VerifyBasicEd25519(ked, pre) {
        let keys = ked["keys"]
            console.log('Keys are ==================>',keys[0])
            console.log("Pre ----------------------------->",pre)
        try {
            if (keys.length != 1)
                return false
            if (keys[0] != pre)
                return false
            if (ked['nxt'])
                return false
        } catch (e) {
            return false
        }
        return true
    }




    /**
     * @description : Verify derivation of fully qualified Base64 prefix from
                      inception key event dict (ked). returns TRUE if verified else raise exception
             * @param {*} ked    ked is inception key event dict
             * @param {*} pre   pre is Base64 fully qualified prefix
     */
    _VerifyDigBlake3_256(ked, pre) {

        let [raw, code,response,crymat] = ''
        try {

            response = _DeriveDigBlake3_256(ked = ked)
            raw = response.raw
            code = response.code

            crymat = new Crymat(raw,null,null, code)
            if (crymat.qb64() != pre)
                return false



        } catch (error) {
            console.log("error is =============>",error)
            return false
        }
        return true

    }



    /**
* @description : Verify derivation of fully qualified Base64 prefix from
    inception key event dict (ked). returns TRUE if verified else raise exception
     * @param {*} ked    ked is inception key event dict
     * @param {*} pre   pre is Base64 fully qualified prefix
     */
    _VerifySigEd25519(ked, pre) {

        let [ilk] = null

        try {

            let [labels, values, ser, keys, verfer, signer, sigver] = null
            ilk = ked["ilk"]
            console.log('ILK -------------------------_>',ked)
            if (ilk == Ilks.icp)
                labels = IcpLabels
            if (ilk == Ilks.icp)
                labels = DipLabels
            else
                throw `Invalid ilk = ${ilk} to derive pre.`

            for (let l in labels) {
                if (!Object.values(ked).includes(l)) { `Missing element = ${l} from ked.` }
            }

            values = extractValues(ked,labels)
            ser = Buffer.from("".concat(values), 'utf-8')
            try {
                if (keys.length != 1)
                    throw `Basic derivation needs at most 1 key got ${keys.length} keys instead`
                verfer = Verfer(qb64 = keys[0])
            } catch (e) {
                throw `Error extracting public key = ${e}`
            }
            if (!(Object.values(derivation_code.oneCharCode.Ed25519).includes(verfer.code()))) {
                throw `Invalid derivation code = ${verfer.code()}`
            }

            sigver = new Sigver(qb64 = pre, verfer = verfer)

            result = sigver.getVerfer.verify(sig = sigver.raw, ser = ser)
            return result

        } catch (exception) {
            return false
        }


    }

}





    /**
     * @description  Returns tuple raw, code of basic Ed25519 prefix (qb64)
                     as derived from key event dict ked
     * @param {*} ked 
     * @param {*} seed 
     * @param {*} secret 
     */
  function  _DeriveBasicEd25519(ked, seed = null, secret = null,code=derivation_code.oneCharCode.Ed25519) {
            let _verfer = null
        try {
            keys = ked["keys"]
            if (keys.length != 1)
                throw `Basic derivation needs at most 1 key got ${keys.length} keys instead`

                console.log("Initializing verfer class--------->")
                _verfer = new Verfer(null,keys[0])
                console.log("_VERFER is --------------->",_verfer)
    
        } catch (e) { throw `Error extracting public key = ${e}` }

        if (!(Object.values(derivation_code.oneCharCode.Ed25519).includes(_verfer.code()))) {
            throw `Invalid derivation code = ${_verfer.code()}.`
        }

        console.log("###############  RAW DATA ED25519 IS ############### :",_verfer.raw())
        return { "raw":_verfer.raw(), "code": _verfer.code() }
    }


    
    
    
    /**
    * @descriptionReturns return  (raw, code) of basic nontransferable Ed25519 prefix (qb64)
    * @param {*} ked  ked is inception key event dict
    * @param {*} seed seed is only used for sig derivation it is the secret key/secret
    * @param {*} secret secret or private key 
    */

   function  _DeriveBasicEd25519N(ked, seed = null, secret = null) {
    let  _verfer = null
       try {
           keys = ked["keys"]
           if (keys.length != 1)
               throw `Basic derivation needs at most 1 key got ${keys.length} keys instead`
               _verfer = new Verfer(null,keys[0])
          console.log("_VERFER is --------------->",_verfer)
       } catch (e) { throw `Error extracting public key = ${e}` }

       if (!(Object.values(derivation_code.oneCharCode.Ed25519N).includes(_verfer.code()))) {
           throw `Invalid derivation code = ${_verfer.code()}.`
       }

       try {
           if ((Object.values(derivation_code.oneCharCode.Ed25519N).includes(_verfer.code())) && ked["nxt"]) {
               throw `Non-empty nxt = ${ked["nxt"]} for non-transferable code = ${_verfer.code()}`
           }
       } catch (e) { throw `Error checking nxt = ${e}` }

       console.log("###############  RAW DATA ED25519N IS ############### :",_verfer.raw())
       return { "raw": _verfer.raw(), "code": _verfer.code() }
   }






       /**
     * @description Returns raw, code of basic Ed25519 pre (qb64)
                    as derived from key event dict ked
     * @param {*} ked  ked is inception key event dict
     * @param {*} seed seed is only used for sig derivation it is the secret key/secret
     * @param {*} secret secret or private key 
     */
  function   _DeriveDigBlake3_256(ked, seed = null, secret = null) {
        let     labels, values, ser, dig = null
        ilk = ked["ilk"]
        console.log("KED are ===========>",ilk)
        if (ilk == Ilks.icp)
            labels = IcpLabels
        else  if (ilk == Ilks.dip)
            labels = DipLabels
        else
            throw `Invalid ilk = ${ilk} to derive pre.`
        console.log("labels =================>",labels)
        for (let l in labels) {
            if (Object.values(ked).includes(l)) { `Missing element = {l} from ked.` }
        }

        values = extractValues(ked,labels)
        ser = Buffer.from("".concat(values), 'utf-8')
        dig = blake3.createHash(ser).digest()
        return { 'raw': dig, 'code': derivation_code.oneCharCode.Blake3_256 }
    }


    /**
     * @description   Returns  raw, code of basic Ed25519 pre (qb64)
                as derived from key event dict ked
     * @param {*} ked  ked is inception key event dict
     * @param {*} seed seed is only used for sig derivation it is the secret key/secret
     * @param {*} secret secret or private key 
     * 
     * 
     */
function  _DeriveSigEd25519(ked, seed = null, secret = null) {
        console.log("INSIDE _DeriveSigEd25519")
        let labels, values, ser, keys, verfer, signer, sigver = null
        ilk = ked["ilk"]
        console.log("ILK is ------->",ilk)
        if (ilk == Ilks.icp){labels = IcpLabels}            
        else if (ilk == Ilks.dip){labels = DipLabels}    
        else
            throw `Invalid ilk = ${ilk} to derive pre.`

        console.log("IcpLabels ================>",IcpLabels)
        for (let l in labels) {
            if (!Object.values(ked).includes(l)) { `Missing element = {l} from ked.` }
        }
        console.log("labels ---------->",labels)
        values = extractValues(ked,labels)
        ser = Buffer.from("".concat(values), 'utf-8')

        try {
            keys = ked["keys"]
            if (keys.length != 1)
                throw `Basic derivation needs at most 1 key  got ${keys.length} keys instead`

            verfer = new Verfer(null,keys[0])
        } catch (exception) {
            throw Error`extracting public key = ${exception}`
        }

        console.log("VERFER CODES ARE :")
        if (verfer.code() != derivation_code.oneCharCode.Ed25519)
            throw `Invalid derivation code = ${verfer.code()}`
        if (!(seed || secret))
            throw `Missing seed or secret.`

        signer = Signer(raw = seed, qb64 = secret)

        if (verfer.raw != signer.verfer.raw)
            throw `Key in ked not match seed.`

        sigver = signer.sign(ser = ser)
        return { 'raw': sigver.raw, 'code': derivation_code.twoCharCode.Ed25519 }

    }

module.exports = { Prefixer }