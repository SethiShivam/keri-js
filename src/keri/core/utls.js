const { isArray } = require("lodash")

function pad(n, width = 3, z = 0) { 
      
    return (String(z).repeat(width) + String(n)).slice(String(n).length)
}

/**
 * @description  Returns list of depth first recursively extracted values from elements of
    key event dict ked whose flabels are in lables list

 * @param {*} ked  ked is key event dict
 * @param {*} labels    labels is list of element labels in ked from which to extract values
 */
function extractValues(ked, labels){

let values = []
console.log("LABELS =========+=>",labels)
for (let label of labels){
    console.log("label is -------->",label)
    extractElementValues(ked[label], values)
}
return values
}




/**
 * @description   Recusive depth first search that recursively extracts value(s) from element
    and appends to values list
    Assumes that extracted values are str

 * @param {*} element 
 * @param {*} values 
 */

function extractElementValues(element, values) {

    console.log("ELEMENT is --------->",typeof(element))
    if((element instanceof Array) && !(element instanceof String)){
            console.log("Inside if ==")
                for(let k in element)
                extractElementValues(k, values)



    }else if (element instanceof String){
        console.log("Inside elseif ==")
        values.push(element)        
    }else  {
        throw `Unexpected element value =  ${element} Not a str.`
    }
}




/**
 * @description Returns True if obj is non-string iterable, False otherwise

 * @param {*} obj   
 */

// function nonStringIterable(obj) {
//     obj instanceof (String)
//     return  instanceof(obj, (str, bytes)) && instanceof(obj, Iterable))
// }


function stringToUint(string) {
    var string = btoa(unescape(encodeURIComponent(string))),
        charList = string.split(''),
        uintArray = [];
    for (var i = 0; i < charList.length; i++) {
        uintArray.push(charList[i].charCodeAt(0));
    }
    return new Uint8Array(uintArray);
}
module.exports = {pad,stringToUint,extractValues}