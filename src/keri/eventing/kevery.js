


// Kevery processes an incoming message stream and when appropriate generates
// an outgoing steam. When the incoming streams includes key event messages
// then Kevery acts a Kever (KERI key event verifier) factory.

const { Logger } = require("../db/database");
const { Serder } = require('../core/serder')
const { Prefixer } = require('../core/prefixer')
const { Kever } = require('../eventing/Kever')
const { Serials, Versionage, IcpLabels, Ilks,SealEvent } = require('../core/core')
const _ = require('lodash');
const { range } = require("lodash");
const { Verfer } = require("../core/verfer");
const { snkey, Logger, dgkey } = require('../db/database')
// Only supports current version VERSION

// Has the following public attributes and properties:

// Attributes:
// .ims is bytearray incoming message stream
// .oms is bytearray outgoing message stream
// .kevers is dict of existing kevers indexed by pre (qb64) of each Kever
// .logs is named tuple of logs
// .framed is Boolean stream is packet framed If True Else not framed
class Kevery {


    constructor(ims = null, oms = null, kevers = null, logger = null, framed = true) {

        if (ims) { this.ims = ims } else {
            this.ims = new Uint8Array(256);
        }

        if (oms) { this.oms = oms } else {
            this.oms = new Uint8Array(256);
        }

        if (framed) { this.framed = true } else {
            this.framed = false
        }

        if (kevers) { this.kevers = kevers } else {
            this.kevers = {}
        }

        if (!logger) { this.logger = new Logger() }
        else {
            this.logger = logger
        }

    }


    /**
 * @description  Process all messages from incoming message stream, ims, when provided
Otherwise process all messages from .ims
 */
    processAll(ims = null) {

        if (ims) {
            if (!(ims instanceof Uint8Array)) {
                ims = new Uint8Array(ims)
            } else {
                ims = this.ims
            }


            while (ims) {
                try {

                    this.processOne(ims, this.framed)
                } catch (error) {
                    throw error
                }
            }
        }
    }


    /**
     * @description Extract one msg with attached signatures from incoming message stream, ims
    And dispatch processing of message
     * @param {*} ims ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
 
    * @param {*} framed framed is Boolean, If True and no sig counter then extract signatures
                        until end-of-stream. This is useful for framed packets with
                         one event and one set of attached signatures per invocation.
     */
    processOne(ims, framed = true) {
        let [serder, nsigs] = null
        //  let nsigs = null
        try {
            serder = new Serder(ims)
        } catch (err) {
            throw `Error while processing message stream = ${err}`
        }

        let version = serder.version()
        if (!_.isEqual(version, Versionage)) {
            throw `Unsupported version = ${version}, expected ${Versionage}.`
        }
        delete ims.slice(0, serder.length)

        let ilk = serder.ked['ilk']  //# dispatch abased on ilk
        let arr = new Array(Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt)
        // let Ilks_arr = []
        if (ilk in arr) {


            try {
                let counter = new Sigcounter(qb64b = ims)
                nsigs = counter.count
                delete ims.slice(0, (counter.qb64).length)
            } catch (error) {
                nsigs = 0
            }

            sigers = []

            if (nsigs) {
                for (let i in range(nsigs)) {
                    siger = new sigers(qb64b = ims)
                    sigers.push(siger)
                    delete ims.slice(0, (siger.qb64()).length)
                }
            }
            else {
                if (framed) {
                    while (ims) {
                        siger = new sigers(qb64b = ims)
                        sigers.push(siger)
                        delete ims.slice(0, (siger.qb64()).length)
                    }
                }
            }

            if (!sigers) {
                throw `Missing attached signature(s).`
            }

            this.processEvent(serder, sigers)
        } else if (ilk in Ilks.rct) {


            try {
                let counter = new CryCounter(qb64b = ims)  //# qb64
                let ncpts = counter.count
                delete ims.slice(0, (counter.qb64).length)
            } catch (error) {
                ncpts = 0
            }

            if (ncpts) {
                for (let i in range(ncpts)) {
                    let verfer = new Verfer(qb64b = ims)
                    delete ims.slice(0, (verfer.qb64()).length)
                    let sigver = new Sigver(qb64b = ims, verfer = verfer)
                    sigvers.push(sigver)
                    delete ims.slice(0, (verfer.qb64()).length)
                }
            } else {
                if (framed) {
                    while (ims) {
                        verfer = new Verfer(qb64b = ims)
                        delete ims.slice(0, (verfer.qb64()).length)

                        let sigver = new Sigver(qb64b = ims, verfer = verfer)
                        sigvers.push(sigver)

                        delete ims.slice(0, (sigver.qb64()).length)
                    }
                }
            }

            if (!sigvers)
                throw `Missing attached receipt couplet(s).`

            this.processReceipt(serder, sigvers)


        } else if (ilk in Ilks.vrc) {
            let nsigs = null
            try {
                let counter = new CryCounter(qb64b = ims)  //# qb64
                nsigs = counter.count
                delete ims.slice(0, (counter.qb64).length)
            } catch (error) {
                nsigs = 0
            }

            if (nsigs) {
                for (let i in range(nsigs)) {
                    let siger = new Siger(qb64b = ims)

                    sigers.push(siger)
                    delete ims.slice(0, (siger.qb64()).length)
                }
            } else {
                if (framed) {
                    while (ims) {
                        siger = new Siger(qb64b = ims)
                        sigers.push(siger)

                        delete ims.slice(0, (siger.qb64()).length)
                    }
                }
            }

            if (!sigers) {
                throw `Missing attached signature(s) to receipt.`
            }

            this.processChit(serder, sigers)
        } else {
            throw `Unexpected message ilk = ${ilk}.`
        }
    }


    /**
     * @description Process one event serder with attached indexd signatures sigers
     * Receipt dict labels
            vs  # version string
            pre  # qb64 prefix
            ilk  # rct
            dig  # qb64 digest of receipted event
     */
    processEvent(serder, sigers) {
        let [prefixer, dig, kever, dgkey, sno] = null

        let ked = serder.ked


        try {
            prefixer = new Prefixer(null, null, null, null, null, ked["pre"])
        } catch (error) {
            throw `Invalid pre = ${ked["pre"]}.`

        }

        let pre = prefixer.qb64()
        let ked = serder.ked
        let ilk = ked["ilk"]

        let sn = ked['sn']
        if (sn.length > 32) {
            throw `Invalid sn = ${sn} too large.`
        }

        try {
            sn = parseInt(sn, 16)
        } catch (error) {
            throw `Invalid sn = ${sn}`
        }

        dig = serder.dig

        //    if(this.logger.getEvt(dgKey(pre, dig))){


        //    }

        if (!(pre in this.kevers)) {
            if (ilk == Ilks.icp) {

                kever = new Kever(serder = serder, sigers = sigers, null, logger = self.logger)

                this.kevers[pre] = kever
            } else {
                dgkey = dgkey(pre, dig)
                this.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                this.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                this.logger.putEvt(dgkey, serder.raw)
                this.logger.addOoes(snKey(pre, sn), dig)
            }
        } else {
            if (ilk == Ilks.icp) {

                dgkey = dgkey(pre, dig)
                this.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                this.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                this.logger.putEvt(dgkey, serder.raw)
                this.logger.addLdes(snKey(pre, sn), dig)
            } else {

                kever = this.kevers[pre] // # get existing kever for pre
                sno = kever.sn + 1  //# proper sn of new inorder event
                if (sn > sno)           //  # sn later than sno so out of order escrow
                {
                    dgkey = dgkey(pre, dig)
                    this.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                    this.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                    this.logger.putEvt(dgkey, serder.raw)
                    this.logger.addOoes(snKey(pre, sn), dig)
                } else if ((sn == sno) ||
                    (ilk == Ilks.rot && kever.lastEst.sn < sn <= sno)) {

                    kever.update(serder = serder, sigers = sigers)

                } else {

                    dgkey = dgkey(pre, dig)
                    this.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                    this.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                    this.logger.putEvt(dgkey, serder.raw)
                    this.logger.addLdes(snKey(pre, sn), dig)
                }




            }


        }

    }



    /**
     * @description  Process one receipt serder with attached sigvers
     * @param {*} serder 
     * @param {*} sigvers 
     */
    processReceipt(serder, sigvers){

       let ked = serder.ked
       let pre = ked["pre"]
       let  sn = ked["sn"]
            let [dig,snkey,ldig,eserder,couplet] = null
       if(sn.length > 32){
        throw `Invalid sn = ${sn} too large.`
       }
       try{
        sn = parseInt(sn,16)
    }catch(error){
        throw `Invalid sn = ${sn}`
    }

    dig = ked["dig"]
   // # Only accept receipt if for last seen version of event at sn
    snkey = snkey(pre=pre, sn=sn)
    ldig = this.logger.getKeLast(key=snkey)   // retrieve dig of last event at sn.


  //  # retrieve event by dig
    dgkey = dgKey(pre=pre, dig=dig)
    raw = self.logger.getEvt(key=dgkey)    //# retrieve receipted event at dig

    if(ldig){

        ldig = ldig.toString('utf-8')
        if(ldig != dig){
            throw `Stale receipt at sn = ${ked["sn"]}`
        }

        eserder =  new Serder(raw=Buffer.from(raw,'binary')) 

        for(sigver in sigvers){
            if(!sigver.verfer.nontrans){
                {}
            }
            if(sigver.verfer.verify(sigver.raw, eserder.raw)){

                couplet = sigver.verfer.qb64b() + sigver.qb64b()
                    this.logger.addRct(key=dgkey, val=couplet)
            }

        }
    }else {
        if(raw){

            throw `Bad receipt for sn = ${ked["sn"]} and dig = ${dig }.`
        }

        for(sigver in sigvers){
            if(!sigver.verfer.nontrans){
                {}
            }
            if(sigver.verfer.verify(sigver.raw, eserder.raw)){

                couplet = sigver.verfer.qb64b() + sigver.qb64b()
                    this.logger.addUre(key=dgkey, val=couplet)
            }

        }
    }
    }



/**
 * @description  Process one transferable validator receipt (chit) serder with attached sigers
 * @param {} serder serder is chit serder (transferable validator receipt message)
 * @param {*} sigers    sigers is list of Siger instances that contain signature

 */
    processChit(serder, sigers){

            let [dig,seal,sealet,snKey,dgKey,ldig,raw,rekever,triplet] = null
       let ked = serder.ked
       let pre = ked["pre"]
       let  sn = ked["sn"]

       if(sn.length > 32){
           throw `Invalid sn = ${sn} too large.`
       }

       try{
           sn = parseInt(sn,16)
       }catch(error){
           throw `Invalid sn = ${sn}`
       }
       dig = ked["dig"]
       seal = SealEvent(ked["seal"])
       sealet = seal.pre.encode("utf-8") + seal.dig.encode("utf-8")


       snKey = snkey(pre=pre, sn=sn)
       ldig = this.logger.getKeLast(key=snkey)  // # retrieve dig of last event at sn.

       dgKey = dgkey(pre=pre, dig=dig)
       raw = this.logger.getEvt(key=dgkey) // # retrieve receipted event at dig

       if(ldig){
           ldig = ldig.toString('utf-8')      
           if(ldig != dig){
               throw `Stale receipt at sn = ${ked["sn"]}`
           }     
       }else {
        if(raw){
            throw `Bad receipt for sn = ${ked["sn"]} and dig = ${dig}.`
        }

       }


    //    # assumes db ensures that:
    //    # if ldig is not None then raw is not None and vice versa
    //    # if ldig == dig then eraw must not be none

    if (ldig !=null && raw !=null && seal.pre in self.kevers){

        rekever = this.kevers[seal.pre]

        if (rekever.lastEst.dig != seal.dig)
        throw `Stale receipt for pre = ${pre} dig = ${dig} from validator = ${seal.pre}.`

        raw = Buffer.from(raw,'binary')

        for (let siger in sigers ){
            if(siger.index >=(rekever.verfers).length){
                throw `Index = ${siger.index} to large for keys.`
            }
            siger.verfer = rekever.verfers[siger.index] 

            if(siger.verfer.verify(siger.raw, raw)){
                triplet = sealet + siger.qb64b()
                    this.logger.addVrc(key=dgkey, val=triplet)
            }else {
                for (let siger in sigers ){
                    triplet = sealet + siger.qb64b
                    this.logger.addVre(key=dgkey, val=triplet)
                }
            }
        }
    }

    }




    /**
     * @description  Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move
     * @param {*} serder 
     * @param {*} sigers 
     */
    duplicity(serder, sigers){

        let [prefixer,pre,ked,ilk,sn,dig] = null
        let ked = serder.ked

        try{
            prefixer = new Prefixer(null,null,null,null,null,qb64=ked["pre"])
        }catch(err){
throw `Invalid pre = ${ked["pre"]}.`
        }

        pre = prefixer.qb64
        ked = serder.ked
        ilk = ked["ilk"]

        try{
            sn = parseInt(ked["sn"], 16)
        }catch(err){
            throw `Invalid sn = ${ked["sn"]}`
        }
        dig = serder.dig



        if (ilk == Ilks.icp){
            kever = new Kever(serder=serder, sigers=siger, logger=self.logger)
        }else {
            {}
        }

    }
}