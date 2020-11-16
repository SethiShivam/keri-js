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
  values =   extractElementValues(ked[label], values)
}
console.log("extractValues are = ",values)
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
        var val_array = []
    console.log("ELEMENT is --------->",element)

    try{
      //  console.log("Inside Try",element instanceof Array ,element instanceof String,typeof(element) == 'string' )
    if((element instanceof Array) && !(typeof(element) == 'string')){
            console.log("Inside if ==")
                for(let k in element)
                extractElementValues(k, values)



    }else if (typeof(element) == 'string'){
        console.log("Inside elseif ==")
        values.push(element)        
    }
    val_array = values
    // else  {
    //     throw `Unexpected element value =  ${element} Not a str.`
    // }
  }catch(error){
      console.log("ERROR caused while calling extractElementValues")
            throw error
    }

    console.log("val_array ==================>",val_array)
    return val_array
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


function range(start, stop, step) {
    if (typeof stop == 'undefined') {
        // one param defined
        stop = start;
        start = 0;
    }

    if (typeof step == 'undefined') {
        step = 1;
    }

    if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) {
        return [];
    }

    var result = [];
    for (var i = start; step > 0 ? i < stop : i > stop; i += step) {
        result.push(i);
    }

    return result;
};


const replacer = (key, value) =>
  value instanceof Object && !(value instanceof Array) ? 
    Reflect.ownKeys(value)
    .reduce((ordered, key) => {
      ordered[key] = value[key];
      return ordered 
    }, {}) :
    value;
module.exports = {pad,stringToUint,extractValues,range,replacer}