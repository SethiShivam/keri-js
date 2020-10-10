const Deque = require("collections/deque");
const derivationCodeLength = require('../core/derivationCode&Length')
function string2Bin(s) {
    var b = new Array();
    var last = s.length;

    for (var i = 0; i < last; i++) {
        var d = s.charCodeAt(i);
        if (d < 128)
            b[i] = dec2Bin(d);
        else {
            var c = s.charAt(i);
            console.log(c + ' is NOT an ASCII character');
            b[i] = -1;
        }
    }
    return b;
}

function dec2Bin(d) {
    var b = '';

    for (var i = 0; i < 8; i++) {
        b = (d%2) + b;
        d = Math.floor(d/2);
    }

    return b;
}

function intToB64(i, l=1){


    let queue = []
    queue.unshift(derivationCodeLength.b64ChrByIdx[i % 64])
    i = Math.floor(i/64)
    console.log("I is --------------->",i)
    
        if(i >0){
            for (let k=0;k <= i;k++) {
                console.log("value of i inside for loop is --------->",k)
                console.log("I is =======================>",derivationCodeLength.b64ChrByIdx[i % 64])
                queue.unshift(derivationCodeLength.b64ChrByIdx[i % 64])
                i= Math.floor(i/64)
                
                console.log("value of i is ",i )
                }
        }
            console.log("que value and length are --------------->",queue,queue.length)
    // do{
    //     queue.unshift(derivationCodeLength.b64ChrByIdx[i % 64])
    //     i= i/64
    //     console.log("value of i is ",i , queue.length)
    // }while(let j < i)
            let length = queue.length

                for(let j = 0 ; j < l-length;j++){
                    queue.unshift(derivationCodeLength.b64ChrByIdx[j % 64])
                    queue.join('')
            console.log("queue join is -------------------->", queue)
                }
            return queue.join('')
}


/**
 * @description Returns conversion of Base64 str cs to int
 * @param {} cs 
 */
function b64ToInt(cs){
    let i = 0 
    // if(cs.length ==1){
    //     i += derivationCodeLength.b64ChrByIdx[cs] * 64 ** index
    //     return i
    // }
    console.log('cs is ------------------_>',cs)
    let splitString = cs.split("")
    let reverseArray = splitString.reverse();

    // var ret = {};
    // for(var key in derivationCodeLength.b64ChrByIdx){
    //   ret[derivationCodeLength.b64ChrByIdx[key]] = key;
    // }
    // console.log(ret) 
    for (const [index, element] of reverseArray.entries()) {
        let keyOfValue = Object.keys(derivationCodeLength.b64ChrByIdx).find(key => derivationCodeLength.b64ChrByIdx[key] === element)
        i += keyOfValue * 64 ** index
      }
      console.log("final value of i is ---------->",i)
    return i 
}
module.exports = {string2Bin,
    intToB64,
    b64ToInt
}