'use strict'
const codeAndLength = require('./derivationCode&Length')
var Base64 = require('urlsafe-base64');
//require('js-base64').Base64;
const intToB64 = require('./../help/stringToBinary')




/**
 *   SigMat is fully qualified attached signature crypto material base class
    Sub classes are derivation code specific.

    Includes the following attributes and properites.

    Attributes:

    Properties:
        .code  str derivation code of cipher suite for signature
        .index int zero based offset into signing key list
               or if from SigCntDex then its count of attached signatures
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given .raw
        .qb64 str in Base64 with derivation code and signature crypto material
        .qb2  bytes in binary with derivation code and signature crypto material
 */
class SigMat {

    //   pad = ""
    //     BASE64_PAD = '='

    constructor(raw = null, qb64 = null, qb2 = null, code = codeAndLength.SigTwoCodex.Ed25519, index = 0) {

        /*
         Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code cipher suite
            index is int of offset index into current signing key list
                   or if from SigCntDex then its count of attached signatures

        When raw provided then validate that code is correct for length of raw
            and assign .raw .code and .index
        Else when either qb64 or qb2 provided then extract and assign .raw and .code

        */


        if (raw) {
            console.log("Inside this.raw condition")
            if (!(Buffer.isBuffer(raw) || Array.isArray(raw))) {
                throw `Not a bytes or bytearray, raw= ${raw}.`
            }
            console.log("Calculating pad value ----------->", raw)
            let pad = this._pad(raw)
            console.log("PAD Value is ------->", pad)

            if (!((pad == 2 && Object.values(JSON.stringify(codeAndLength.SigTwoCodex)).includes(code))
                || (pad == 0 && Object.values(JSON.stringify(codeAndLength.SigCntCodex).includes(code))
                    || (pad == 0 && Object.values(JSON.stringify(codeAndLength.SigFourCodex).includes(code))
                        || (pad == 1 && Object.values(JSON.stringify(codeAndLength.SigFiveCodex).includes(code))))))) {
                throw `Wrong code= ${code} for raw= ${raw} .`
            }
            if ((Object.values(codeAndLength.SigTwoCodex).includes(code)
                && (index < 0) || (index > codeAndLength.SIGTWOMAX))
                || (Object.values(codeAndLength.SigCntCodex).includes(code) && ((index < 0) || (index > codeAndLength.SIGFOURMAX)))
                || (Object.values(codeAndLength.SigFourCodex).includes(code) && ((index < 0) || (index > codeAndLength.SIGFOURMAX))) ||
                (Object.values(codeAndLength.SigFiveCodex).includes(code) && ((index < 0) || (index > codeAndLength.SIGFIVEMAX)))) {
                throw `Invalid index=${index} for code=${code}.`
            }
            //   console.log('codeAndLength.cryAllRawSizes[this.code]-------->',codeAndLength.cryAllRawSizes[this.code])

            raw = raw.slice(0, codeAndLength.SigRawSizes[code])
            console.log("raw value after slicing is --->", raw.length)
            if (raw.length != codeAndLength.SigRawSizes[code]) {
                throw `Unexpected raw size= ${raw.length} for code= ${code}"
                " not size= ${codeAndLength.cryAllRawSizes[code]}.`
            }
            this._code = code
            console.log("updated code is -------------->", Buffer.from(raw, 'binary'))
            this._index = index
            this._raw = Buffer.from(raw, 'binary')  // crypto ops require bytes not bytearray

        }


        else if (qb64 != null) {
            qb64 = qb64.toString('utf-8')
            console.log("qb64---------------->", qb64)
            this._exfil(qb64)
        }
        else if (qb2 != null) {
            //  encodeB64(qb2).decode("utf-8")
            console.log("qb2 ----->", Base64.encode(qb2))
            this._exfil(Base64.encode(qb2))
        } else {
            throw 'Improper initialization need raw or b64 or b2.'
        }
    }


    _pad(raw) {
        let reminder = Buffer.byteLength(raw, 'binary') % 3
        if (reminder == 0)
            return 0
        else {
            return 3 - reminder
        }
    }

    _exfil(qb64) {
        let BASE64_PAD = '='
        console.log("qb64 length is --------------> ", qb64.length)
        let cs = 1   //code size
        let code_slice = qb64.slice(0, cs)
        console.log("slicing code is ------------->", code_slice)
        let index = 0

        if (Object.values(codeAndLength.SigTwoCodex).includes(code_slice)) {
            console.log("codeAndLength.SigTwoCodex[code_slice] ---------------->", codeAndLength.CryOneSizes[code_slice])
            qb64 = qb64.slice(0, codeAndLength.SigTwoSizes[code_slice])
            cs += 1
            index = Object.keys(codeAndLength.b64ChrByIdx).find(key => codeAndLength.b64ChrByIdx[key] === qb64.slice(cs - 1, cs))

        }

        else if (code_slice == codeAndLength.SigSelectCodex.four) {
            cs += 1
            code_slice = qb64.slice(0, cs)
            console.log("code slice is ---------------->", code_slice)
            if (!Object.values(codeAndLength.SigFourCodex).includes(code_slice))
                throw `Invalid derivation code = ${code_slice} in ${qb64}.`

            qb64 = qb64.slice(0, codeAndLength.SigFourSizes[code_slice])
            console.log("qb64 Details are :-------------->", qb64.length)
            cs += 2
            index = Object.keys(codeAndLength.b64ChrByIdx).find(key => codeAndLength.b64ChrByIdx[key] === qb64.slice(cs - 2, cs))
        }

        else if (code_slice == codeAndLength.SigSelectCodex.dash) {
            cs += 1
            // console.log("cs inside dash is ------>",cs)
            code_slice = qb64.slice(0, cs)
            // console.log("code after slicing is ------->",code_slice)
            // console.log("Code is present in crySelectCodex.four \n",codeAndLength.SigSelectCodex.four)
            if (!Object.values(codeAndLength.SigCntCodex).includes(code_slice))
                throw `Invalid derivation code = ${code_slice} in ${qb64}.`

            qb64 = qb64.slice(0, codeAndLength.SigCntSizes[code_slice])
            cs += 2
            console.log("qb64 and cs value are ------------------->", qb64, cs)
            index = Object.keys(codeAndLength.b64ChrByIdx).find(key => codeAndLength.b64ChrByIdx[key] === qb64.slice(cs - 2, cs))
        }


        else {
            throw `Improperly coded material = ${qb64}`
        }

        if (qb64.length != codeAndLength.SigSizes[code_slice])
            throw `Unexpected qb64 size= ${qb64.length} for code= ${code_slice} not size= ${codeAndLength.cryAllSizes[code_slice]}.`

        let pad = cs % 4
        console.log("qb64 length is -------------->", qb64.length)
        console.log("Pad value is ------------>", pad)
        console.log("cs value is ------------>", cs)
        console.log("qb64[cs:] ------------>", qb64.slice(cs, qb64.length))
        let base = qb64.slice(cs, qb64.length) + BASE64_PAD.repeat(pad)
        console.log("Base is ------>", base)
        let decoded_base = Base64.decode(base.toString('utf-8'))    //Buffer.from(base, "utf-8")
        console.log("RAW value ============================:", index)
        if (decoded_base.length != Math.floor(((qb64.length - cs) * 3) / 4)) {
            throw `Improperly qualified material = ${qb64}`
        }
        this._code = code_slice
        this._raw = Buffer.from(decoded_base, 'binary')
        this._index = parseInt(index)
        this._qb64 = qb64



    }

    _infil() {

        let l = codeAndLength.SigIdxSizes[this._code]
        console.log("Value of l is ===========>", l)
        let full = `${this._code}${intToB64.intToB64(this._index, l = l)}`
        console.log("Value of full is ===========>", full)
        let pad = this.pad()
        // Validate pad for code length
        console.log("PAD ==============>", pad)
        if ((full).length % 4 != pad) {
            // Here pad is not the reminder of code length
            throw `Invalid code = ${this.code} for converted raw pad = ${this.pad}.`
        }
        console.log("FULL -------->",decodeURIComponent(Base64.encode(this.raw())))
        // console.log("Base64.encode(this.raw) -------->",Base64.encode(this.raw), '',(Base64.encode(this.raw)).length)
        //  console.log("pad ---------------_>",(Base64.encode(this.raw)).slice(0, -pad))
        //encodeURIComponent(Base64.encode(this._raw))
        
        return (full + decodeURIComponent(Base64.encode(this.raw())))
        //.slice(0, -pad))
    }

    qb64() {
        // qb64 = Qualified Base64 version,this will return qualified base64 version assuming
        // self.raw and self.code are correctly populated

        return this._infil()
    }

    /**
     * """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
     */
    qb64b() {
        return Buffer.from(this.qb64, 'utf-8')
    }


    qb2() {
        /* Property qb2:
         Returns Fully Qualified Binary Version Bytes
         redo to use b64 to binary decode table since faster
         """
         # rewrite to do direct binary infiltration by
         # decode self.code as bits and prepend to self.raw
         */
        //  Buffer.from(this._infil(), 'utf-8')

        return Base64.decode(Buffer.from(this._infil(), 'binary')).toString('utf-8')
    }

    raw() {
        console.log("this._raw", this._raw)
        return this._raw
    }

    pad() {
        return this._pad(this._raw)
    }

    code() {
        return this._code

    }
    index() {
        return this._index
    }
}


module.exports = { SigMat }