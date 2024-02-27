function copyOfRange(src, start, end, dst, destOff) {
    for (let i = start; i < end; i++) {
        dst[destOff] = src[i];
        destOff++;
    }
}
function arrayCopy(src, srcPos, dst, dstPos, length) {
    while (length--) {
        dst[dstPos++] = src[srcPos++];
    }
    // console.log(dst);
}

function hexStrToUint8(str){
    if(str.length % 2 !== 0) throw `Invalid hex string length (${str.length})` 
    return new Uint8Array(str.split('').reduce((acc, _, idx) => {
        if(idx % 2 == 0) {
            acc.push(parseInt(str[idx] + str[idx+1], 16))
        }
        return acc
    }, []))
}

function uint8ToHexStr(arr){
    return Array.from(arr).map(c => c.toString(16).padStart(2,'0')).join('')
}

// module.exports = {
//     copyOfRange,
//     arrayCopy,
// };
