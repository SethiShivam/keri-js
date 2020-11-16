
const { Versionage, Serials, deversify,versify,MINSNIFFSIZE } = require('../core/core')
const codeAndLength = require('./derivationCode&Length')
const _ = require('lodash')
var msgpack = require('msgpack5')() // namespace our extensions
  , encode  = msgpack.encode
  , decode  = msgpack.decode
var cbor = require('cbor');
var blake3 = require('blake3')
const {Diger} = require('../core/diger')
const {replacer} = require('./utls')
const XRegExp = require('xregexp');
const { encodeURI } = require('js-base64');
/**
 * @description  Serder is KERI key event serializer-deserializer class
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .version is Versionage instance of event version
        .size is int of number of bytes in serialed event only
 */
class Serder {

  /**
   * 
   *@description   Deserialize if raw provided
      Serialize if ked provided but not raw
      When serilaizing if kind provided then use kind instead of field in ked

      Parameters:
        raw is bytes of serialized event plus any attached signatures
        ked is key event dict or None
          if None its deserialized from raw
        kind is serialization kind string value or None (see namedtuple coring.Serials)
          supported kinds are 'json', 'cbor', 'msgpack', 'binary'
          if kind is None then its extracted from ked or raw
        size is int number of bytes in raw if any


      Attributes:
        ._raw is bytes of serialized event only
        ._ked is key event dict
        ._kind is serialization kind string value (see namedtuple coring.Serials)
          supported kinds are 'json', 'cbor', 'msgpack', 'binary'
        ._version is Versionage instance of event version
        ._size is int of number of bytes in serialed event only
        ._diger is Diger instance of digest of .raw

      Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .version is Versionage instance of event version
        .size is int of number of bytes in serialed event only
        .diger is Diger instance of digest of .raw
        .dig  is qb64 digest from .diger
        .digb is qb64b digest from .diger

      Note:
        loads and jumps of json use str whereas cbor and msgpack use bytes
   */
  constructor(raw = Buffer.from('', 'binary'), ked = null, kind = null) {

      console.log("INSIDE SERDER CONSTRUCTOR :")
    if (raw)
      this._raw = raw
    else if (ked) {
      this._ked = ked
      this._kind = kind
    }
    else throw 'Improper initialization need raw or ked.'

  }



  /**
   * @description  Returns serialization kind, version and size from serialized event raw
                   by investigating leading bytes that contain version string
   * @param {buffer bytes} raw 
   */

  _sniff(raw) {
   
 
        let [major,minor,kind,size] = ''
      if(raw.length < MINSNIFFSIZE)
      throw `"Need more bytes."`

      const version_pattern = Buffer.from('KERI(?<major>[0-9a-f])(?<minor>[0-9a-f])(?<kind>[A-Z]{4})(?<size>[0-9a-f]{6})_','binary')
      const regex = XRegExp(version_pattern)
      let response =  XRegExp.exec(raw,regex)


      console.log("Response is ------------>",response.major)
      console.log("REGEX Match is --------->",response )

      if (!(response) || response.kind > 12)
      throw `Invalid version string in raw = ${raw}`

      major = response.major
      minor = response.minor
      kind  = response.kind
      size = response.size
      console.log("major,minor,kind,size are ----------->",major,minor,kind,raw.length)
      // response.minor,response.kind,response.size
      Versionage.major = parseInt(major, 16)
      Versionage.minor = parseInt(minor, 16)
      let version = Versionage
      console.log("VERSION  IS --------->",kind)
      kind = kind.toString()

      if (!(Object.values(Serials).includes(kind))){
        console.log("Condition Failed ==============>")
        throw `Invalid serialization kind = ${kind}`
      }
 
      size = parseInt(size, 16)
  return[kind, version, size]







    //let match = re.exec(raw)
        //let match = version_pattern.exec(raw)
      //   let t = Buffer.from(raw,'binary')
      //  let match_string = raw.match(re)
  }



  /**
   * @description Parses serilized event ser of serialization kind and assigns to
          instance attributes.  
    @NOTE :
            loads and jumps of json use str whereas cbor and msgpack use bytes  
            
   * @param {*} raw raw is bytes of serialized event
   * @param {}  kind kind is str of raw serialization kind (see namedtuple Serials)
   * @param {} size size is int size of raw to be deserialized
   */
    _inhale(raw) {


    let [kind, version, size] = this._sniff(raw)
    let ked = null
    if (!(_.isEqual(version, Versionage)))
      throw `Unsupported version = ${Versionage.major}.${Versionage.minor}`

    if ((raw).length < size)
      throw `Need more bytes`
    if (kind == Serials.json) {
      try {
        console.log("Raw is -------->",size)
        ked = JSON.parse((raw).slice(0, size))
      } catch (error) {
        console.log("ERROE is ",error)
        throw error
      }
    }
    else if (kind == Serials.mgpk) {
      try {
        ked = decode(decodeURIComponent(raw.slice(0, size)))

      } catch (error) {
        throw error
      }
    } else if (kind == Serials.cbor) {
      try {
        ked = cbor.decodeFirst(encoded, function (error, obj) {
          if (error)
            return error
          else
            return obj
        });

      } catch (error) {
        throw error
      }
    }
    else ked = null

    return [ ked, kind,  version,  size ]
  }




  /**
   * @description ked is key event dict
                   kind is serialization if given else use one given in ked
                    Returns tuple of (raw, kind, ked, version) where:
   * @param {*} ked ked is key event Json
   * @param {*} kind kind is serialzation kind
   */
  _exhale(ked, kind = null) {
    let raw,fore,back= null

    if (Object.values(JSON.stringify(ked)).includes('vs'))
      throw `Missing or empty version string in key event dict =${ked}`

    let [knd, version, size] = deversify(ked['vs'])
    console.log("Version ------------>",version)
    if (!(_.isEqual(version, Versionage)))
      throw `Unsupported version = ${Versionage.major}.${Versionage.minor}`

    if (!kind)
      kind = knd

    if (!(Object.values(Serials).includes(kind))){
      console.log("Condition Failed ==============>")
      throw `Invalid serialization kind = ${kind}`
    }
      

    if (kind == Serials.json){
      console.log("We are here ==============>")
      raw = JSON.stringify(ked,replacer) 
    }
     

    else if (kind == Serials.mgpk)
      raw = encode(ked).toString('hex')

    else if (kind == Serials.cbor)
      raw = cbor.dumps(ked)

    else {
      throw `Invalid serialization kind = ${kind}`
    }
      console.log("Value of Raw is -------->",raw)
     size = raw.length
 const version_pattern = Buffer.from('KERI(?<major>[0-9a-f])(?<minor>[0-9a-f])(?<kind>[A-Z]{4})(?<size>[0-9a-f]{6})_','binary')
 //let re = new RegExp(version_pattern) 
  const regex = XRegExp(version_pattern)

//  let abc =  XRegExp.matchRecursive(Buffer.from(raw),'\\(', '\\)', 'g');
 let response =    XRegExp.exec(Buffer.from(raw),regex)
//let match = re.exec(raw)
    //let match = version_pattern.exec(raw)
  //   let t = Buffer.from(raw,'binary')
  //  let match_string = raw.match(re)
      console.log("REGEX Match is --------->",response.lastIndexOf(response.kind,response.index) )
    // let search = raw.search(version_pattern)
    if (!(response) || response.kind > 12)
      throw `Invalid version string in raw = ${raw}`

// while (match = re.exec(raw)) {
//   console.log(match.index + ' ' + re.lastIndex);
//   fore = match.index
//   back = re.lastIndex
//     match ++ 
// }

let vs = versify(version,kind,size)

let traw = Buffer.from('%b%b%b','binary') % (raw.slice(0,fore), encodeURIComponent(vs), raw.slice(response.lastIndexOf(response.kind,7),raw.length))
console.log("Size and Traw are --------->",size,traw.length)
if(size != raw.length)
    throw `Malformed version string size = ${vs}`

    ked['vs'] = vs 

    return [raw, kind, ked,version]
  }


  raw(){
    
    return this._raw

  }

  set_raw(raw){
    console.log("INSIDE SET_RAW ==================>")
  let [ ked, kind, version, size]  = this._inhale(raw)
    this._raw = Buffer.from(raw.slice(0,size),'binary') // # crypto ops require bytes not bytearray
    this._ked = ked
    this._kind = kind
    this._version = version
    this._size = size
    const hasher = blake3.createHash();
    let dig = blake3.hash(this._raw);
    let digest = hasher.update(this._raw).digest('')
    this._diger =  new Diger(digest,null,
                        codeAndLength.oneCharCode.Blake3_256)

  }

  ked(){

    return this._ked
  }

  set_ked(){

    let [ raw, kind, ked, version]  = this._exhale(raw)
    this._raw = Buffer.from(raw.slice(0,size),'binary') // # crypto ops require bytes not bytearray
    size = raw.length
    this._ked = ked
    this._kind = kind
    this._version = version
    this._size = size
    const hasher = blake3.createHash();
    let dig = blake3.hash(this._raw);
    let digest = hasher.update(this._raw).digest('')
    this._diger =  new Diger(raw=digest,null,
                        code=codeAndLength.oneCharCode.Blake3_256)

  }

  kind(){

    return this._kind
  }

  set_kind(){
    
    let  [raw, kind, ked, version]  = this._exhale(this._ked)
    console.log(" raw, kind, ked, version ============>", raw, kind, ked, version)
    size = raw.length
    this._raw = raw.slice(0,size)
    this._ked = ked
    this._kind = kind
    this._size = size
    this._version = version

  }

  version(){

    return this._version
  }
  size(){
return this._size
  }

  diger(){
    const hasher = blake3.createHash();
    let dig = blake3.hash(this._raw);
    let digest = hasher.update(this._raw).digest('')
    this._diger =  new Diger(digest,null,
                        codeAndLength.oneCharCode.Blake3_256)
    return this._diger
  }

  dig(){
      let diger = this.diger()
      console.log("DIger ------->",diger)

    return diger.qb64()
  }

  digb(){
    let diger = this.diger()
    return diger.qb64b()
  }
}


module.exports = {Serder}


