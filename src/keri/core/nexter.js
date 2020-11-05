const { Diger } = require('./diger')
const { encode } = require('utf8')
const _ = require('lodash')


/**
 * @description  Nexter is Diger subclass with support to create itself from
                    next sith and next keys
 */

class Nexter extends Diger {


    /**
     * 
 Assign digest verification function to ._verify

        See CryMat for inherited parameters

        Parameters:
           ser is bytes serialization from which raw is computed if not raw
           sith is int threshold or lowercase hex str no leading zeros
           keys is list of keys each is qb64 public key str

           Raises error if not any of raw, ser, keys, ked

           if not raw and not ser
               If keys not provided
                  get keys from ked

           If sith not provided
               get sith from ked
               but if not ked then compute sith as simple majority of keys
     */
    constructor(ser = null, sith = null, keys = null, ked = null) {
        // let a = null
       var response = null
        try {
            console.log("value of Ser is -----------------_>",ser)
            super(null, ser)
        } catch (error) {
            console.log("INSIDE ERROR ==================>")
            if (!keys && !ked) {
                throw error
            }
            console.log("sith, keys, ked==========================>", sith, keys, ked)
              response = _derive(sith, keys, ked)    
            super(null, response.ser)
            this.response = response
        }
            console.log("RESPONSE ===========================+>",response.sith)
        if (response.sith) {
            console.log("sith is ------------------>",response.sith)
            this._sith = _.cloneDeep(response.sith)
        } else
            this._sith = null
        if (response.keys)
            this._keys = _.cloneDeep(response.keys)
        else
            this._keys = null


    }

    /**
     * """ Property ._sith getter """
     */
    sith() {
        return this._sith
    }

    /**
   * """ Property ._keys getter """
   */
    keys() {
        return this._keys
    }

    derive(sith = null, keys = null, ked = null) {


        return _derive(sith, keys, ked)
    }

    /**
     * @description    Returns True if digest of bytes serialization ser matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code  If ser not provided then extract ser from either (sith, keys) or ked
     * @param {*} ser 
     * @param {*} sith 
     * @param {*} keys 
     * @param {*} ked 
     */
    verify(ser = Buffer.from('', 'binary'), sith = null, keys = null, ked = null) {

        if (!ser) {
            let { ser, sith, keys } = this._derive(sith, keys, ked)
        }


        return this._verify(ser, this.raw())
    }
}

/**
* 
@description Returns serialization derived from sith, keys, or ked
*/
 function  _derive(sith = null, keys = null, ked = null) {
    console.log("inside drive function================>", sith, keys, ked)
    let nxts = []
    let _ser = null
    if (!keys) {
        console.log("inside keys ===================>", keys)
        try {

            keys = ked["keys"]
            console.log("keys --================>", ked['keys'])
        } catch (error) {
            throw `Error extracting keys from ked = ${error}`
        }
    }
    if (!keys)
        throw "Keys not found"
    if (!sith) {
        console.log("if not sith ===================================>")
        try {
            sith = ked["sith"]
        } catch (error) {

            sith = Math.max(1, Math.ceil((keys).length / 2))
        }
    }
    if (sith instanceof Array) {
        `List form of sith = ${sith} not yet supporte`
    }
    else {
        try {
            sith = parseInt(sith, 16)
        } catch (error) { }
        sith = Math.max(1, sith)
        sith = sith.toString(16)
    }
     nxts = [Buffer.from(sith, 'binary')]  // create list to concatenate for hashing   sith.toString("utf-8")
    console.log("nxts before adding keys ----------->", nxts)
    keys.forEach((key) => {
        console.log("key inside keys is ------------>", keys)
        nxts.push(Buffer.from(key, 'binary'))
    })      
    _ser = Buffer.from(nxts.join(''), 'binary')
  console.log("ser is ====================>",_ser)
    return { ser: _ser, sith: sith, keys: keys }

}




module.exports = { Nexter }