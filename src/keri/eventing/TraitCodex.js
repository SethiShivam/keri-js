
const { Serialage, Serials, versify, Ilks,Versionage } = require('../core/core')
const _ = require('lodash')
const { Prefixer } = require('../core/prefixer')
const { Serder } = require('../core/serder')
const derivationCodeLength = require('../core/derivationCode&Length')
const ICP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
    "toad", "wits", "cnfg"]
const ROT_LABELS = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt",
    "toad", "cuts", "adds", "data"]
const IXN_LABELS = ["vs", "pre", "sn", "ilk", "dig", "data"]
const DIP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
    "toad", "wits", "perm", "seal"]
const DRT_LABELS = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt",
    "toad", "cuts", "adds", "perm", "seal"]


/**
 * @description    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
 */
class TraitCodex {


    constructor() { }



    /**
     * @description Returns serder of inception event message.
        Utility function to automate creation of inception events.
     */
    incept(keys,
        code = null,
        version = Versionage,
        kind = Serials.json,
        sith = null,
        nxt = "",
        toad = null,
        wits = null,
        cnfg = null,
    ) {

        let vs = versify(version, kind, 0)
        let sn = 0
        let ilk = Ilks.icp
        let prefixer = null
          console.log("type fo sithis ",typeof(7))  
        if (sith == null) {
            console.log("INside null -------->")
            sith = Math.max(1, Math.ceil(keys.length / 2))
        }
        if (typeof(sith) == 'number') {
            if (sith < 1 || sith > keys.length)
                throw `Invalid sith = ${sith} for keys = ${keys}`
        }
        else
            throw `invalid sith = ${sith}.`


        if (!wits)
            wits = []

        if ((isSorted(wits)).length != wits.length)
            `Invalid wits = ${wits}, has duplicates.`

        if (toad == null) {
            console.log("toad  = null",wits.length)
            if (wits.length == 0) {
                toad = 0
            } else
                toad = Math.max(1, Math.ceil(wits.length / 2))
        }

        if (wits.length != 0) {
            console.log("Inside wits ------->",wits)
            if (toad < 1 || toad > wits.length)
                throw `Invalid toad = ${toad} for wits = ${wits}`
        } else {
            if (toad != 0)
                throw `Invalid toad = ${toad} for wits = ${wits}`
        }


        if (!cnfg)
            cnfg = []

        let ked = {
            vs: vs,         // version string
            pre: "",                                       //# qb64 prefix
            sn: sn.toString(16),             // # hex string no leading zeros lowercase
            ilk: ilk,
            sith: sith.toString(16),             //# hex string no leading zeros lowercase
            keys: keys,                            //# list of qb64
            nxt: nxt,                              //# hash qual Base64
            toad: toad.toString(16),             //  # hex string no leading zeros lowercase
            wits: wits,                            // # list of qb64 may be empty
            cnfg: cnfg,                           // # list of config ordered mappings may be empty
        }
        console.log(" =========================  Keys are ------------------>",code,keys.length )
        if (code == null && keys.length == 1) {
            prefixer = new Prefixer(null, derivationCodeLength.oneCharCode.Ed25519N, null, null, null, keys[0])
        }
        else {
            console.log("========================CODE BEFORE PREFIX IS =======================",code)
            prefixer = new Prefixer(null, code, ked)
        }

        ked["pre"] = prefixer.qb64()
        return new Serder(null, ked)
    }


    /**
     * @description  Returns serder of rotation event message.
    Utility function to automate creation of rotation events.
     */
    rotate(pre,
        keys,
        dig, sn = 1,
        version = Versionage,
        kind = Serials.json,
        sith = null,
        nxt = "",
        toad = null,
        wits = null,      //# prior existing wits
        cuts = null,
        adds = null,
        data = null,
    ) {


        let cutset,addset = null
        console.log("Value of sith is ------>",sith)
        let vs = versify(version, kind, 0)
        //let sn = 0
        let ilk = Ilks.rot
        let prefixer = null

        if (sn < 1) {
            `Invalid sn =  ${sn} for rot.`
        }
        if (sith == null) {
            console.log("INSIDE Sith == null")
            sith =   Math.max(1, Math.ceil(keys.length / 2))
        }
        if (typeof(sith) == 'number') {
            if (sith < 1 || sith > keys.length)
                throw `Invalid sith = ${sith} for keys = ${keys}`
        }
        else
            throw `invalid sith = ${sith}.`


        if (!wits) wits = []

        let witset = wits
        if ((witset).length != wits.length)
            `Invalid wits = ${wits}, has duplicates.`


        if (!cuts) cuts = []
        
        cutset = cuts
        console.log("cutset --------------->",witset,cutset)
        if(!(_.isEqual(witset,cutset)))
        throw `Invalid cuts = ${cuts}, not all members in wits.`

        if (!adds) adds = []

         addset = adds
        console.log("value of adds is ------->",addset)
    
        if(addset.length != adds.length )
        throw  `Invalid adds =  ${adds}, has duplicates.`

        console.log("Value of cutset and addset are : =======>",cutset,addset)
        if((cutset.length > 0) && (addset.length > 0)) throw `Intersecting cuts = ${cuts} and  adds = ${adds}.`
        
        if((witset.length > 0) && (addset.length > 0)) throw `Intersecting wits = ${wits} and  adds = ${adds}.`

        let newitset = witset.filter(x => !cutset.includes(x));

        if((newitset.length) != (wits.length -cuts.length + adds.length) )
        throw   `Invalid member combination among wits = ${wits}, cuts = ${cuts},and adds = ${adds}.`


        if(!toad){
            console.log("TOAD ABSENT ",newitset)
            if(newitset.length ==0){toad = 0}
            else {toad = Math.max(1, Math.ceil(newitset.length / 2))}
        }
        if(newitset.length > 0){
            if(toad <1 || toad > newitset.length)
            throw `Invalid toad = ${toad} for resultant wits = ${newitset}`
        }else {
            if(toad !=0) {throw `Invalid toad = ${toad} for resultant wits = ${newitset}`}
        }

        if (!adds) adds = []

        let ked = {
            vs: vs,         // version string
            pre: pre,                                       //# qb64 prefix
            sn: sn.toString(16),             // # hex string no leading zeros lowercase
            ilk: ilk,
            dig :dig,
            sith: sith.toString(16),             //# hex string no leading zeros lowercase
            keys: keys,                            //# list of qb64
            nxt: nxt,                              //# hash qual Base64
            toad: toad.toString(16),             //  # hex string no leading zeros lowercase
            cuts :cuts,   //  # list of qb64 may be empty
            adds :adds,    // # list of qb64 may be empty
            data :data,  // # list of seals                      // # list of config ordered mappings may be empty
        }


        return new Serder(null, ked)
    }


    /**
     * @description  Returns serder of interaction event message.
    Utility function to automate creation of interaction events.
     */

     interact(pre,
        dig,
        sn=1,
        version=Versionage,
        kind=Serials.json,
        data=null,
       ){
        let vs = versify(version, kind, 0)
        //let sn = 0
        let ilk = Ilks.ixn
        let prefixer = null
 
        if (sn < 1) {
         `Invalid sn =  ${sn} for rot.`
     }


     if (!data) data = []


     let ked = {
        vs: vs,         // version string
        pre: pre,                                       //# qb64 prefix
        sn: sn.toString(16),             // # hex string no leading zeros lowercase
        ilk: ilk,
        dig :dig,
        data :data,  // # list of seals                      // # list of config ordered mappings may be empty
    }


    return new Serder(null, ked)
       }



       /**
        * @description Returns serder of event receipt message for non-transferable receipter prefix.
                        Utility function to automate creation of interaction events.
        * @param {*} pre   pre is qb64 str of prefix of event being receipted
        * @param {*} sn     sn  is int sequence number of event being receipted
        * @param {*} dig    dig is qb64 of digest of event being receipted
        * @param {*} version    version is Version instance of receipt
        * @param {*} kind       kind  is serialization kind of receipt
        */
       receipt(pre,
        sn,
        dig,
        version=Versionage,
        kind=Serials.json
       ){


        let vs = versify(version, kind, 0)
        //let sn = 0
        let ilk = Ilks.rct

        if (sn < 1) {
            `Invalid sn =  ${sn} for rct.`
        }

        let ked = {
            vs:vs,      //# version string
            pre:pre,  //# qb64 prefix
            ilk:ilk,  //#  Ilks.rct
            sn:sn.toString(16),  //# hex string no leading zeros lowercase
            dig:dig,    //# qb64 digest of receipted event
        }

        return new Serder(null, ked)
       }

/**
 * @description   Returns serder of validator event receipt message for transferable receipter
    prefix.
    Utility function to automate creation of interaction events.
 * @param {} pre     pre is qb64 str of prefix of event being receipted
 * @param {*} sn     sn  is int sequence number of event being receipted
 * @param {*} dig   dig is qb64 of digest of event being receipted
 * @param {*} seal   seal is namedTuple of SealEvent of receipter's last Est event
 * @param {*} version    version is Version instance of receipt
 * @param {*} kind          kind  is serialization kind of receipt
 */

       chit(pre,
        sn,
        dig,
        seal,
        version=Versionage,
        kind=Serials.json
       ){

        let vs_ = versify(version, kind, 0)
        //let sn = 0
        let ilk = Ilks.vrc

        if (sn < 1) {
            `Invalid sn =  ${sn} for vrc.`
        }

        let ked = {
            vs :vs_,          // # version string
            pre:pre,        //# qb64 prefix
            ilk:ilk,            //#  Ilks.vrc
            sn:sn.toString(16),   // # hex string no leading zeros lowercase
            dig:dig,        // # qb64 digest of receipted event
            seal:seal         //  # event seal: pre, dig
        }
        return new Serder(null, ked)

       }
}


function isSorted(array) {
    const limit = array.length - 1;
    for (let i = 0; i < limit; i++) {
        const current = array[i], next = array[i + 1];
        if (current > next) { return false; }
    }
    return true;
}


module.exports = {isSorted,TraitCodex}