
const { Serials, Versionage, IcpLabels, Ilks } = require('../core/core')
const { snkey, Logger,dgkey } = require('../db/database')
const { LastEstLoc } = require('../../keri/eventing/util')
const { Prefixer } = require('../core/prefixer')
const { Nexter } = require('../core/nexter')
const { isSorted, TraitCodex } = require('./TraitCodex')
const { Serder } = require('../core/serder')
const verfer = require('../core/verfer')
const { keys, times } = require('lodash')
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
 * """
    Kever is KERI key event verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Class Attributes:
        .EstOnly is Boolean
                True means allow only establishment events
                False means allow all events

    Attributes:
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .diger is Diger instance with digest of current event not prior event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .verfers is list of Verfer instances for current event state set of signing keys
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .cnfg is list of inception configuration data mappings
        .estOnly is boolean
        .nonTrans is boolean
        .lastEst is LastEstLoc namedtuple of int .sn and qb64 .dig of last est event

    Properties:

        .nonTransferable  .nonTrans

    """
 */



class Kever {
    


    constructor(serder, sigers, estOnly = null, logger = null) {

        if (!logger) {
            logger = new Logger()
        }

        this.logger = logger
        this.version = serder.version       // # version dispatch ?
        this.verfers = serder.verfers           //# converts keys to verifiers
        this.EstOnly = false

        for (let siger in sigers) {

            if (siger.index >= (self.verfers).length) {

                throw `Index = ${siger.index} to large for keys.`
            }
            siger.verfer = this.verfers[siger.index]        //# assign verfer



        }

        let ked = serder.ked

        for (let k in IcpLabels) {
            if (!Object.keys(JSON.stringify(ked)).includes(k)) {
                throw `Missing element = ${k} from ${Ilks.icp}  event.`
            }


        }

        let ilk = ked["ilk"]
        if (ilk != Ilks.icp) {
            throw `Expected ilk = ${Ilks.icp} got ${ilk}.`
        }
        this.ilk = ilk
        let sith = ked["sith"]
        if (sith instanceof String) {
            this.sith = parseInt(sith, 16);

            if (this.sith < 1 || this.sith > (this.verfers).length)
                throw `Invalid sith = ${sith} for keys = ${this.verfers.qb64()}`
            else {
                throw `Unsupported type for sith = ${sith}`
            }
        }
        this.prefixer = new Prefixer(qb64 = ked["pre"])
        //null,null,null,null,null,ked["pre"])
        if (!this.prefixer.verify(ked["pre"])) {
            throw `Invalid prefix = ${this.prefixer.qb64()} for inception ked = ${ked}.`
        }


        sn = ked["sn"]
        if (sn.length > 32) {
            `Invalid sn = ${sn} too large.`
        }

        try {
            parseInt(sith, 16)
        } catch (error) {
            `Invalid sn = ${sn}`

        }
        if (sn != 0) {
            `Nonzero sn = ${sn} for inception ked = ${ked}.`
        }
        this.sn = sn
        this.diger = serder.diger

        let nxt = ked['nxt']
        if (nxt) {
            this.nexter = new Nexter(qb64 = nxt)
        } else this.nexter = new Nexter()

        if (!this.nexter) {
            this.nonTrans = true
        } else {
            this.nonTrans = false
        }

        let wits = ked['wits']
        if (isSorted(wits).length != wits.length) {
            `Invalid wits = ${wits}, has duplicates.`
        }
        this.wits = wits

        let toad = parseInt(ked['toad'], 16);

        if (wits) {
            if (toad < 1 || toad > wits.length) {
                `Invalid toad = ${toad} for wits = ${wits}`
            }
        } else {
            if (toad != 0)
                throw `Invalid toad = ${toad} for wits = ${wits}`
        }

        this.toad = toad
        this.cnfg = ked['cnfg']

        if (!estOnly) {
            estOnly - this.EstOnly
            this.estOnly = true
        }

        let traitcodex = new TraitCodex()
        for (let d in this.cnfg) {
            if ((Object.keys(JSON.stringify(d)).includes('trait')) && d['trait'] == traitcodex.EstOnly()) {

            }
        }

    }






    /**
     * @description :  Not original inception event. So verify event serder and
        indexed signatures in sigers and update state
     * @param {*} serder 
     * @param {*} sigers 
     */

    update(serder, sigers) {

        if (this.nonTrans) {
            throw `Unexpected event = ${serder} in nontransferable  state.`
        }

        let ked = serder.ked
        let pre = ked['pre']
        let sn = ked["sn"]

        if (sn.length > 32) {
            throw `Invalid sn = ${sn} too large.`
        }


        try {

            sn = parseInt(sn, 16)
        } catch (error) {
            throw `Invalid sn = ${sn}`
        }
        if (sn == 0) {
            throw `Zero sn = ${sn} for non=inception ked = ${ked}.`
        }

        let dig = ked['dig']
        let ilk = ked['ilk']

        if (pre != this.prefixer.qb64())
            throw `Mismatch event aid prefix = ${pre} expecting = ${this.prefixer.qb64()}.`

        if (ilk == Ilks.rot) {
            for (let k in ROT_LABELS) {
                if (!(k in ked))
                    throw `Missing element = ${k} from ${Ilks.rot}  event.`
            }

            if (sn > this.sn + 1)   // Out of order event 
            {
                throw `Out of order event sn = ${sn} expecting= ${this.sn + 1}.`
            } else if (sn <= this.sn) {

                // # stale or recovery
                // #  stale events could be duplicitous
                // #  duplicity detection should have happend before .update called
                // #  so raise exception if stale


                if (sn <= this.lastEst.sn) {
                    throw `Stale event sn = ${sn} expecting= ${this.sn + 1}.`
                }
                else {
                    if (this.ilk != Ilks.ixn) {
                        throw `Invalid recovery attempt: Recovery at ilk = ${this.ilk} not ilk = ${Ilks.ixn}.`
                    }

                    let psn = sn - 1 // sn of prior event 
                    this.logger = new Logger()
                    let pdig = this.logger.getKeLast(key = snkey(pre = pre, sn = psn))

                    if (!pdig) {
                        throw `Invalid recovery attempt: Recovery at ilk = ${this.ilk} not ilk = ${Ilks.ixn}. `
                    }

                    let praw = this.logger.getEvt(key = dgKey(pre = pre, dig = pdig))
                    if (!praw) {
                        throw `Invalid recovery attempt: Bad dig = ${pdig}.`
                    }


                    let pserder = new Serder(Buffer.from(praw, 'binary'))
                    if (dig != pserder.dig()) {
                        throw `Invalid recovery attempt:
                       Mismatch recovery event prior dig= ${dig} with dig = ${pserder.dig()} of event sn = ${psn}.`
                    }
                }

            }

            else {
                if (dig != this.diger.qb64) {
                    throw `Mismatch event dig = ${dig} with state dig = ${this.dig.qb64()}.`
                }
            }

            if (!this.nexter) {
                throw `Attempted rotation for nontransferable prefix = ${this.prefixer.qb64()}`
            }

            let verfers = serder.verfers()

            let sith = ked["sith"]
            if (sith instanceof String) {
                sith = parseInt(sith, 16)
                if (sith < 1 || sith > (this.verfers).length) {
                    throw `Invalid sith = ${sith} for keys = ${verfer}`
                }
            } else {
                throw `Unsupported type for sith = ${sith}`
            }

            let keys = ked['keys']

            if (!(this.nexter.verify(null, sith, keys))) {
                throw `Mismatch nxt digest = ${this.nexter.qb64()} with rotation sith = ${sith}, keys = ${keys}.`
            }



            // # verify nxt from prior
            // # also check derivation code of pre for non-transferable
            // #  check and

            if (!this.nexter) {
                throw `Attempted rotation for nontransferable prefix = ${this.prefixer.qb64()}`
            }

            verfers = serder.verfers()   //# only for establishment events

            sith = ked['sith']
            if (sith instanceof String) {
                sith = parseInt(sith, 16)
                if (sith < 1 || sith > (this.verfers).length) {
                    throw `Invalid sith = ${sith} for keys = ${this.verfers}`
                }
            } else {
                throw `Unsupported type for sith = ${sith}`
            }

            keys = ked['keys']
            if (!(this.nexter.verify(null, sith, keys))) {
                throw `Mismatch nxt digest = ${this.nexter.qb64()} with rotation sith = ${sith}, keys = ${keys}.`
            }

            let witset = isSorted(this.wits)
            let cuts = ked['cuts']
            cutset = isSorted(cuts)
            if (cutset.length != cuts.length) {
                throw `Invalid cuts = ${cuts}, has duplicates.`
            }

            if (witset != cutset && cutset != cutset) {
                throw `Invalid cuts = ${cuts}, not all members in wits.`
            }


            let adds = ked["adds"]
            let addset = isSorted(adds)
            if (addset.length != adds.length) {
                throw `Invalid adds = ${adds}, has duplicates.`
            }

            if (cutset && addset) {
                throw `Intersecting cuts = ${cuts} and  adds = ${adds}.`
            }
            if (witset & addset) {
                throw `Intersecting cuts = ${this.wits} and  adds = ${adds}.`
            }
            wits = [witset.filter(n => !cutset.includes(n))] || [addset]

            if (wits.length != ((this.wits).length - cuts.length + adds.length)) {
                throw `Invalid member combination among wits = ${this.wits}, cuts = ${cuts}, "
            "and adds = ${adds}.`
            }

            let toad = parseInt(ked['toad'], 16)
            if (wits) {
                if (toad < 1 || toad > wits.length) {
                    throw `Invalid toad = ${toad} for wits = ${wits}`
                }

            } else {
                if (toad != 0)
                    throw `Invalid toad = ${toad} for wits = ${wits}`
            }

            for (let siger in sigers) {
                if (siger.index() >= verfers.length) {
                    throw `Index = ${siger.index()} to large for keys.`
                }

                siger.verfer = verfers[siger.index]   //assign verfer
            }

            if (!this.verifySigs(sigers = sigers, serder = serder)) {
                throw `Failure verifying signatures = ${siger} for ${serder}`
            }

            if (!this.verifySith(sigers = sigers, serder = serder)) {
                this.escrowEvent(serder, sigers, this.prefixer.qb64b(), sn)
                throw `Failure verifying sith = ${siger}  on sigs for ${sigers}`
            }


            this.sn = sn
            this.diger = serder.diger
            this.ilk = ilk
            this.sith = sith
            this.verfers = verfers
            nxt = ked["nxt"]

            if (nxt) {
                this.nexter = new Nexter(qb64 = nxt)
                if (!this.nexter) {
                    this.nonTrans = true
                }
            }
            this.toad = toad
            this.wits = wits
            this.lastEst = LastEstLoc(sn = this.sn, dig = this.diger.qb64())

            this.logEvent(serder, sigers)  // # update logs
        }
        else if (ilk == Ilks.ixn) {

            if (this.estOnly) {
                throw `Unexpected non-establishment event = ${serder}.`
            }
            for (let k in IXN_LABELS) {
                if (!(k in ked))
                    throw `Missing element = ${k} from ${Ilks.ixn}  event.`
            }

            if (!(sn == this.sn + 1))   // Out of order event 
            {
                throw `Invalid sn = ${sn} expecting = ${this.sn + 1}.`
            }
            if (dig != this.diger.qb64()) {
                throw `Mismatch event dig = ${dig} with state dig = ${this.dig.qb64()}.`
            }


            // # interaction event use keys from existing Kever
            // # use prior .verfers
            // # verify indexes of attached signatures against verifiers

            for (let siger in sigers) {
                if (siger.index() >= verfers.length) {
                    throw `Index = ${siger.index()} to large for keys.`
                }

                siger.verfer = verfers[siger.index]   //assign verfer
            }

            if (!this.verifySigs(sigers = sigers, serder = serder)) {
                throw `Failure verifying signatures = ${siger} for ${serder}`
            }

            if (!this.verifySith(sigers = sigers, serder = serder)) {
                this.escrowEvent(serder, sigers, this.prefixer.qb64b(), sn)
                throw `Failure verifying sith = ${siger}  on sigs for ${sigers}`
            }

            // # update state
            this.sn = sn
            this.diger = serder.diger
            this.ilk = ilk

            this.logEvent(serder, sigers)       // # update logs

        } else {
            throw `Unsupported ilk = ${ilk}.`
        }



    }



    /**
     * @description Use verfer in each siger to verify signature against serder
        Assumes that sigers with verfer already extracted correctly wrt indexes
     * @param {*} sigers  sigers is list of Siger instances
     * @param {*} serder serder is Serder instance
     */
    verifySigs(sigers, serder) {

        for (let siger in sigers){
            if(!(siger.verfer.verify(siger.raw, serder.raw))){
                return false
            }
            
        }
        if (sigers.length <1)
            return false

            return true
    }





/**
 * @description Assumes that all sigers signatures were already verified
        If sith not provided then use .sith instead
  * @param {*} sigers  sigers is list of Siger instances
     * @param {*} serder serder is Serder instance
 */
    verifySith(sigers, sith=null){

        if (!sith)
         sith = this.sith 

         if (!(sith instanceof int))
         throw `Unsupported type for sith =${sith}`

         if(sigers.length < sith.length)
         return false 

        return true
    }


    /**
     * @description Update associated logs for verified event
 * @param {*} sigers  sigers is list of Siger instances
     * @param {*} serder serder is Serder instance
     */
    logEvent(serder, sigers){


        let dgkey = dgkey(this.prefixer.qb64b(), this.diger.qb64b())

        this.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
        this.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
        this.logger.putEvt(dgkey, serder.raw)
        this.logger.addKe(snKey(this.prefixer.qb64b(), this.sn), this.diger.qb64b())

    }
}

module.exports = {Kever}