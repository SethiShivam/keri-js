'use strict'
const codeAndLength = require('./derivationCode&Length')
var Base64 = require('urlsafe-base64');
const intToB64 = require('./../help/stringToBinary')
/**
 * @description CRYPTOGRAPHC MATERIAL BASE CLASS
 * @subclasses  provides derivation codes and key event element context specific
 * @Properties 
 *         .code  str derivation code to indicate cypher suite
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given raw
        .qb64 str in Base64 with derivation code and crypto material
        .qb2  bytes in binary with derivation code and crypto material
 */
class Crymat {

    //   pad = ""
    //     BASE64_PAD = '='

    constructor(raw = null, qb64 = null, qb2 = null, code = codeAndLength.oneCharCode.Ed25519N, index = 0) {

        /*
          Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        When raw provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64 or qb2 provided extract and assign .raw and .code
        */

        console.log("raw length is ----->", raw)
        console.log("Code ----->", code)
        ///typeof(this.raw)== typeof(Buffer.from('', 'binary') ||typeof(this.raw)== typeof(Buffer.from('', 'binary'))))
        if (raw) {
            console.log("Inside this.raw condition")
            if (!(Buffer.isBuffer(raw) || Array.isArray(raw))) {
                throw `Not a bytes or bytearray, raw= ${raw}.`
            }
            console.log("Calculating pad value ----------->", raw)
            let pad = this._pad(raw)
            console.log("PAD Value is ------->", pad)

            // this.raw = Buffer.byteLength(raw, 'utf-8')

            if (!((pad == 1 && Object.values(JSON.stringify(codeAndLength.CryOneSizes)).includes(code))
                || (pad == 2 && Object.values(JSON.stringify(codeAndLength.CryTwoSizes).includes(code))
                    || (pad == 0 && Object.values(JSON.stringify(codeAndLength.CryFourSizes).includes(code)))))) {
                throw `Wrong code= ${code} for raw= ${raw} .`
            }
            if (Object.values(codeAndLength.CryCntCodex).includes(code)
                && (index < 0) || (index > codeAndLength.CRYCNTMAX)) {
                throw `Invalid index=${index} for code=${code}.`
            }
            //   console.log('codeAndLength.cryAllRawSizes[this.code]-------->',codeAndLength.cryAllRawSizes[this.code])

            raw = raw.slice(0, codeAndLength.cryAllRawSizes[code])
            console.log("raw value after slicing is --->", raw.length)
            if (raw.length != codeAndLength.cryAllRawSizes[code]) {
                throw `Unexpected raw size= ${raw.length} for code= ${code}"
                " not size= ${codeAndLength.cryAllRawSizes[code]}.`
            }
            this._code = code
            console.log("updated code is -------------->", code)
            this._index = index
            this._raw = Buffer.from(raw, 'binary')  // crypto ops require bytes not bytearray

        }


        else if (qb64 != null) {
            qb64 = qb64.toString('utf-8')
            console.log("qb64---------------->", qb64)
            this._exfil(qb64)
        }
        else if (qb2 != null) {

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
        if (Object.values(codeAndLength.oneCharCode).includes(code_slice)) {
            console.log("codeAndLength.CryOneSizes[code_slice] ---------------->", codeAndLength.CryOneSizes[code_slice])
            qb64 = qb64.slice(0, codeAndLength.CryOneSizes[code_slice])
            console.log('QB value and length is ---------------->', qb64, '\n', qb64.length)
        }

        else if (code_slice == codeAndLength.crySelectCodex.two) {
            cs += 1
            code_slice = qb64.slice(0, cs)
            console.log("code slice is ---------------->", code_slice)
            if (!Object.values(codeAndLength.twoCharCode).includes(code_slice))
                throw `Invalid derivation code = ${code_slice} in ${qb64}.`

            qb64 = qb64.slice(0, codeAndLength.CryTwoSizes[code_slice])
            console.log("qb64 Details are :-------------->", qb64.length)
        }

        else if (code_slice == codeAndLength.crySelectCodex.four) {
            cs += 3
            code_slice = qb64.slice(0, cs)
            console.log("Code is present in crySelectCodex.four \n", crySelectCodex.four)
            if (!Object.values(codeAndLength.fourCharCode).includes(code_slice))
                throw `Invalid derivation code = ${code_slice} in ${qb64}.`

            qb64 = qb64.slice(0, codeAndLength.CryFourSizes[code_slice])
        }
        else if (code_slice == codeAndLength.crySelectCodex.dash) {
            console.log("Code is present in crySelectCodex.dash \n", codeAndLength.crySelectCodex.dash)
            cs += 1
            code_slice = qb64.slice(0, cs)
            console.log("Code slice is ----------------->", code_slice)
            if (!Object.values(codeAndLength.CryCntCodex).includes(code_slice))
                throw `Invalid derivation code = ${code_slice} in ${qb64}.`

            qb64 = qb64.slice(0, codeAndLength.CryCntSizes[code_slice])
            cs += 2  // increase code size
            index = intToB64.b64ToInt(qb64.slice(cs - 2, cs))
          //  index = Object.keys(codeAndLength.b64ChrByIdx).find(key => codeAndLength.b64ChrByIdx[key] === qb64.slice(cs - 2, cs)) // last two characters for index
            console.log('Value of index is ------>', qb64.slice(cs - 2, cs))
        }

        else {
            throw `Improperly coded material = ${qb64}`
        }

        if (qb64.length != codeAndLength.cryAllSizes[code_slice])
            throw `Unexpected qb64 size= ${qb64.length} for code= ${code_slice} not size= ${codeAndLength.cryAllSizes[code_slice]}.`

        let pad = cs % 4
        console.log("Pad value is ------------>", pad)
        console.log("qb64[cs:] ------------>", qb64.slice(cs, qb64.length))
        let base = qb64.slice(cs, qb64.length) + BASE64_PAD.repeat(pad)
        console.log("Base is ------>", base)
        let raw = Base64.decode(base.toString('utf-8'))    //Buffer.from(base, "utf-8")
        console.log("RAW value and length are :", (Buffer.from(raw, 'binary')).length, '\n', Math.floor(((qb64.length - cs) * 3) / 4))
        if (raw.length != Math.floor(((qb64.length - cs) * 3) / 4)) {
            throw `Improperly qualified material = ${qb64}`
        }
        this._code = code_slice
        this._raw = Buffer.from(raw, 'binary')
        this._index = parseInt(index)
        this._qb64 = qb64



    }

    _infil() {
        let l = null
        let full = null
        console.log("this.code ------------->", this._code)
        if (Object.values(codeAndLength.CryCntCodex).includes(this._code)) {
            console.log("Inside if condition")
          l = codeAndLength.CryCntIdxSizes[this._code]
        full = `${this._code}${intToB64.intToB64(this._index, l = l)}`
        } else {

            full = this._code

        }
            console.log("value of l and full are : ", l ,'\n', full)
        let pad = this.pad()
        // Validate pad for code length
        console.log("PAD ==============>", full)
        if ((full).length % 4 != pad) {
            // Here pad is not the reminder of code length
            throw `Invalid code = ${this._code} for converted raw pad = ${this._pad}.`
        }
        console.log("FULL -------->",full + Base64.encode(this._raw))
        // console.log("Base64.encode(this.raw) -------->",Base64.encode(this.raw), '',(Base64.encode(this.raw)).length)
        //  console.log("pad ---------------_>",(Base64.encode(this.raw)).slice(0, -pad))

        return (full + Base64.encode(this._raw))
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
        return encodeURIComponent(this.qb64())
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

        return Base64.decode(encodeURIComponent(this._infil())).toString()  
    }

    raw() {
        return this._raw
    }

    pad() {
        return this._pad(this._raw)
    }

    code() {
        return this._code

    }

    index() {
        console.log("thiss._index ===========>",this._index)
        return this._index

    }
}


module.exports = { Crymat }