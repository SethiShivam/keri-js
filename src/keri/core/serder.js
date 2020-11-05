
const { Versionage, Serials, deversify,versify } = require('../core/core')
const _ = require('lodash')
const msgpack = require('msgpack5')()
var cbor = require('cbor');
const {Diger} = require('../core/diger')
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

    const version_pattern = 'KERI\(\?P<major>\[0\-9a\-f\]\)\(\?P<minor>\[0\-9a\-f\]\)\(\?P<kind>\[A\-Z\]\{4\}\)\(\?P<size>\[0\-9a\-f\]\{6\}\)_'
    let match = version_pattern.exec(raw)
    let total_matches = raw.matchAll(version_pattern)
    let total_subgroups = []

    for (const subgroups of total_matches) { total_subgroups.push(subgroups) }

    let search = raw.search(version_pattern)
    if (!(match) || search > 12)
      throw `Invalid version string in raw = ${raw}`
    let [major, minor, kind, size] = total_subgroups

    Versionage.major = parseInt(major, 16)
    Versionage.minor = parseInt(minor, 16)

    let version = versionage
    kind = decodeURIComponent(kind)

    if (!Object.values(JSON.stringify(Serials)).includes(kind))
      throw `Invalid serialization kind = ${kind}`

    size = parseInt(size, 16)
    return { 'kind': kind, 'version': version, 'size': size }
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

    if (!(_.isEqual(version, Versionage)))
      throw `Unsupported version = ${Versionage.major}.${Versionage.minor}`

    if ((raw).length < size)
      throw `Need more bytes`
    if (kind == Serials.json) {
      try {
        ked = JSON.parse(decodeURIComponent(raw.slice(0, size)))
      } catch (error) {
        throw error
      }
    }
    else if (kind == Serials.mgpk) {
      try {
        ked = msgpack.decode(decodeURIComponent(raw.slice(0, size)))

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

    return { 'ked': ked, 'kind': kind, 'version': version, 'size': size }
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
    if (!(_.isEqual(version, Versionage)))
      throw `Unsupported version = ${Versionage.major}.${Versionage.minor}`

    if (!kind)
      kind = knd

    if (!(Object.values(JSON.stringify(Serials)).includes(kind)))
      throw `Invalid serialization kind = ${kind}`

    if (kind == Serials.json)
      raw = json.dumps(ked, separators = (",", ":"), ensure_ascii = False).encode("utf-8")

    else if (kind == Serials.mgpk)
      raw = msgpack.dumps(ked)

    else if (kind == Serials.cbor)
      raw = cbor.dumps(ked)

    else {
      throw `Invalid serialization kind = ${kind}`
    }

    size = raw.length
 const version_pattern = 'KERI\(\?P<major>\[0\-9a\-f\]\)\(\?P<minor>\[0\-9a\-f\]\)\(\?P<kind>\[A\-Z\]\{4\}\)\(\?P<size>\[0\-9a\-f\]\{6\}\)_'
    let match = version_pattern.exec(raw)
    // let total_matches = raw.matchAll(version_pattern)

    let search = raw.search(version_pattern)
    if (!(match) || search > 12)
      throw `Invalid version string in raw = ${raw}`

while (match_response = version_pattern.exec(raw)) {
  console.log(match_response.index + ' ' + version_pattern.lastIndex);
  fore = match_response.index
  back = version_pattern.lastIndex

}

vs = versify(version,kind,size)

raw = Buffer.from('%b%b%b','binary') % (raw.slice(0,fore), vs.encode("utf-8"), raw.slice(back,raw.length))
if(size != raw.length)
    throw `Malformed version string size = ${vs}`

    ked['vs'] = vs 

    return {'raw' :raw, 'kind' : kind, 'ked' : ked, 'version' : version}
  }


  raw(){

    this.raw

  }

  set_raw(raw){
  let [ ked, kind, version, size]  = this._inhale(raw)
    this._raw = Buffer.from(raw.slice(0,size),'binary') // # crypto ops require bytes not bytearray
    this._ked = ked
    this._kind = kind
    this._version = version
    this._size = size
    this._diger =  new Diger(raw=blake3.blake3(self._raw).digest(),null,
                        code=CryOneDex.Blake3_256)

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
    this._diger =  new Diger(raw=blake3.blake3(self._raw).digest(),null,
                        code=CryOneDex.Blake3_256)

  }

  kind(){

    return this._kind
  }

  set_kind(){
    
    let  raw, kind, ked, version  = this._exhale(this._ked,kind)
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
    return this._diger
  }

  dig(){

    return this.diger.qb64
  }

  digb(){

    return this.diger.qb64b
  }
}


module.exports = {Serder}

