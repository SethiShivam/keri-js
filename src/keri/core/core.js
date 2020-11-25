const util = require('./utls')


const VERRAWSIZE = 6
var Versionage = { major: 1, minor: 0 }
var Serialage = { json: "", mgpk: "", cbor: "" }
var Vstrings = Serialage
let Serials = { json: "JSON", mgpk: "MGPK", cbor: "CBOR" }
let Ilks = {icp : "icp",rot : "rot",ixn : "ixn",dip : "dip",drt : "drt",rct :"rct",vrc : "vrc"}
let IcpLabels = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt","toad", "wits", "cnfg"]
let DipLabels = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt","toad", "cuts", "adds", "perm", "seal"]


let mimes = {
  json: "application/keri+json",
  mgpk: "application/keri+msgpack",
  cbor: "application/keri+cbor",
}
// let yourNumber = 899
// let hexString =  yourNumber.toString(16);
// let two = '29'.toString(16);
// let three = '39'.toString(16)
//let VERFMT = `KERI${hexString} ${two} ${three}_`   /// version format string
let VERFULLSIZE = 17 
let MINSNIFFSIZE = 12 + VERFULLSIZE 
//nameString.toString("utf8");

// console.log("hexString", VERFMT)

/**
 * @description  It will return version string 
 */
function versify(version=null, kind=Serials.json, size) {
console.log("Inside Versify Method -------------------->")
console.log("value are version,kind,size---------------->",version ,'\n',kind,'\n',size)
  if (!(Object.values(Serials).indexOf(kind) > -1))
   {throw "Invalid serialization kind =", kind.toString(16)} 

 console.log("We are here ")   
  if (!version)
    version = Versionage

    console.log("VERSION  : \n",version['minor'])
  let hex1 = version['major'].toString(16)
  let hex2 = version['minor'].toString(16)
  let kind_hex = kind.toString(16)
  let hex3 = util.pad(size.toString(16), VERRAWSIZE)
  console.log("kind -------->",kind_hex)
  
  console.log('version[0]----------->',version['major'])
  console.log('version[1]---------->',version['minor'])
  console.log('KERI${hex1}${hex2}${kind_hex}${hex3}_[1]---------->',`KERI${hex1}${hex2}${kind_hex}${hex3}_`)
  return `KERI${hex1}${hex2}${kind_hex}${hex3}_`
}



Vstrings.json = versify(version = "", kind = Serials.json, size = 0)
Vstrings.mgpk = versify(version = "", kind = Serials.mgpk, size = 0)
Vstrings.cbor = versify(version = "", kind = Serials.cbor, size = 0)


const version_pattern = 'KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
const version_pattern1 = `KERI\(\?P<major>\[0\-9a\-f\]\)\(\?P<minor>\[0\-9a\-f\]\)\(\?P<kind>\[A\-Z\]\{4\}\)\(\?P<size>\[0\-9a\-f\]\{6\}\)_`
const VEREX = "KERI([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})_"

// Regex pattern matching 

/**
 * @description This function is use to deversify the version 
 * Here we will use regex to  to validate and extract serialization kind,size and version 
 * @param {string} vs   version string
 * @return {Object}  contaning kind of serialization like cbor,json,mgpk   
 *                    version = version of object ,size = raw size integer
 */
function deversify(versionString) {
  let kind, size, version = Versionage
  console.log("versionString ------_>",versionString)
  // we need to identify how to match the bffers pattern like we do regex matching for strings
  let sub_matches = []
  let re = new RegExp(VEREX) 
 
 let match = re.exec(versionString)
//  while (match = versionString.match(VEREX)) {
//   sub_matches.push(match)
// }
  // let match = version_pattern.match(versionString)
  console.log("Match is ------------------>",match)
  if (match) {
    [version.major, version.minor, kind, size] = [match[1], match[2], match[3], match[4]]
    console.log("Value of kind is -------->",kind)
    if (!Object.values(Serials).includes(kind))
      throw `Invalid serialization kind = ${kind}`
    return [kind,  version,  size ]

  }
  return `Invalid version string = ${versionString}`
}

module.exports = {deversify,versify,Versionage,Ilks,Serialage,Serials,IcpLabels,DipLabels,Vstrings,MINSNIFFSIZE}