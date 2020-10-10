const {Crymat} = require('./cryMat')
const codeAndLength = require('./derivationCode&Length')


/**
 * @description : CryCounter is subclass of CryMat, cryptographic material,
                  CryCrount provides count of following number of attached cryptographic
                  material items in its .count property.
                  Useful when parsing attached receipt couplets from stream where CryCounter
                  instance qb64 is inserted after Serder of receipt statement and
                  before attached receipt couplets.
 */
class  CryCounter extends Crymat{

constructor(raw=null, qb64b=null, qb64=null, qb2=null, code=codeAndLength.CryCntCodex.Base64,index=null, count=null, ...kwf){
        console.log("value of raww is --------->",raw ,qb64,qb2,code,index,count)
        if((raw!=null))
                raw = Buffer.from('','binary')
        if(raw == null && qb64 == null && qb64b == null && qb2 ==null )

        raw = Buffer.from('','binary')
        if(count != null)
        index = count
        if(index == null)
        index = 1
        
        super(raw, qb64, qb2, code,index, count, ...kwf)
        if(!(Object.values(codeAndLength.CryCntCodex).includes(this.code())))
                    throw `Invalid code = ${this.code} for CryCounter.`        
}


/**
 * @description  Property counter:
        Returns .index as count
        Assumes ._index is correctly assigned
 */
count(){
return this._index
}

}


module.exports = {CryCounter}