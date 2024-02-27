/* eslint-disable no-bitwise */

// Comments left to show these are required but BigQuery libraries don't use requires/paths.
// const bigInt = require('big-integer');
// const Bn = require('./Bn');
// const { arrayCopy } = require('./arrayUtil');
// const errorMessages = require('./errorMessages');
// const { createCipheriv } = require('crypto');


/* utf.js - UTF-8 <=> UTF-16 convertion
 *
 * Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>
 * Version: 1.0
 * LastModified: Dec 25 1999
 * This library is free.  You can redistribute it and/or modify it.
 */

function Utf8ArrayToStr(array) {
    var out, i, len, c;
    var char2, char3;

    out = "";
    len = array.length;
    i = 0;
    while(i < len) {
    c = array[i++];
    switch(c >> 4)
    { 
      case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        // 0xxxxxxx
        out += String.fromCharCode(c);
        break;
      case 12: case 13:
        // 110x xxxx   10xx xxxx
        char2 = array[i++];
        out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
        break;
      case 14:
        // 1110 xxxx  10xx xxxx  10xx xxxx
        char2 = array[i++];
        char3 = array[i++];
        out += String.fromCharCode(((c & 0x0F) << 12) |
                       ((char2 & 0x3F) << 6) |
                       ((char3 & 0x3F) << 0));
        break;
    }
    }

    return out;
}

class FFX {
    constructor(key, twk, txtmax, twkmin, twkmax, radix, custom_radix_str) {
        let txtmin = 0;
        this.radix = 0;
        this.txtmin = 0;
        this.txtmax = 0;
        this.twkmin = 0;
        this.twkmax = 0;
        this.twk = [];
        this.custom_radix_str = undefined;

        // this.cipher = null;
        /*
         * FF1 and FF3-1 support a radix up to 65536, but the
         * implementation becomes increasingly difficult and
         * less useful in practice after the limits below.
         */
        if (radix < 2 || radix > 36) {
            // throw new Error('invalid radix');
        }

        /*
         * for both ff1 and ff3-1: radix**minlen >= 1000000
         *
         * therefore:
         *   minlen = ceil(log_radix(1000000))
         *          = ceil(log_10(1000000) / log_10(radix))
         *          = ceil(6 / log_10(radix))
         */
        txtmin = parseInt(Math.ceil(6.0 / Math.log10(radix), 10), 10);
        if (txtmin < 2 || txtmin > txtmax) {
            throw new Error('minimum text length out of range');
        }

        /* the default tweak must be specified */
        if (!twk) {
            throw new Error('invalid tweak');
        }
        /* check tweak lengths */
        if (twkmin > twkmax || twk.length < twkmin || (twkmax > 0 && twk.length > twkmax)) {
            throw new Error('invalid tweak length');
        }

        const iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000")
        this.keyArrayBuffer = CryptoJS.enc.Base64.parse(key);
        this.iv = iv;
        
        this.setCipher()

        this.radix = radix;
        this.txtmin = txtmin;
        this.txtmax = txtmax;
        this.twkmin = twkmin;
        this.twkmax = twkmax;
        this.twk = [...twk];
        this.custom_radix_str = custom_radix_str;
    }

    setCipher(){
        this.Cipher = CryptoJS.algo.AES.createEncryptor(this.keyArrayBuffer, { iv: this.iv, padding: CryptoJS.pad.NoPadding });
    }

    /*
     * perform an aes-cbc encryption (with an IV of 0) of @src, storing
     * the last block of output into @dst. The number of bytes in @src
     * must be a multiple of 16. @dst and @src may point to the same
     * location but may not overlap, otherwise. @dst must point to a
     * location at least 16 bytes long
     */
    prf(dst, doff, src, soff, len) {
        const blksz = 16; // Should be something like this.Cipher.getBlockSize or getCiherInfo.block size
        if ((src.length - soff) % blksz !== 0) {
            throw new Error('invalid source length');
        }
        // Output (Uint8)
        let tempResult;
        // CryptoJS Output (CryptoJS.WordLib)
        let crypto;

        for (let i = 0; i < len && i < src.length - soff; i += blksz) {
            const temp = new Uint8Array(blksz);
            arrayCopy(src, soff + i, temp, 0, blksz); // arrayUtil
            
            // Convert UInt8 to representation CryptoJS accepts
            const hexTemp = uint8ToHexStr(temp)
            crypto = this.Cipher.process(CryptoJS.enc.Hex.parse(hexTemp))
        }
        this.Cipher.finalize();

        // Convert Hex String back to Uint8
        const cryptoStr = crypto.toString(CryptoJS.enc.Hex)
        tempResult = hexStrToUint8(cryptoStr)

        for (let j = 0; j < tempResult.length; j++) {
            dst[j + doff] = tempResult[j];
        }
        // reset Cipher
        this.setCipher()
    }

    /*
     * perform an aes-ecb encryption of @src. @src and @dst must each be
     * 16 bytes long, starting from the respective offsets. @src and @dst
     * may point to the same location or otherwise overlap
     */
    ciphh(dst, doff, src, soff) {
        this.prf(dst, doff, src, soff, 16);
    }

    /*
     * a convenience version of the ciph function that returns its
     * output as a separate byte array
     */
    ciph(dst, doff, src, off) {
        this.prf(dst, doff, src, off, 16);
    }

    /*
     * convenience function that returns the reversed sequence
     * of bytes as a new byte array
     */
    rev(src) {
        const dst = [...src];
        return dst.reverse();
    }

    /*
     * reverse the characters in a string
    */

    revStr(str) {
        return [...str].reverse().join('');
    }

    /*
     * Perform an exclusive-or of the corresponding bytes
     * in two byte arrays
     */
    xor(d, doff, s1, s1off, s2, s2off, len) {
        for (let i = 0; i < len; i++) {
            d[doff + i] = s1[s1off + i] ^ s2[s2off + i];
        }
    }

    /*
     * convert a big integer to a string under the radix @r with
     * length @m. If the string is longer than @m, the function fails.
     * if the string is shorter that @m, it is zero-padded to the left
    i: type bigInt
    r: int Radix
    m: length
    */

    str(m, r, i) {
        if (!this.custom_radix_str) {
            const s = i.toString(r);
            if (s.length > m) {
                throw new Error(errorMessages.StringExceeds);
            } else if (s.length < m) {
                return s.padStart(m, '0'); // TODO - This may not be safe if custom_radix_str[0] is not the '0' character
            }
            return s;
        }
        const s = bigint_get_str(this.custom_radix_str, i);
        if (s.length > m) {
            throw new Error(errorMessages.StringExceeds);
        } else if (s.length < m) {
            return s.padStart(m, this.custom_radix_str[0]);
        }
        return s;
    }

    /**
     * Encrypt a string, returning a cipher text using the same alphabet.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF3_1 object.
     *
     * @param X   the plain text to be encrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the encryption of the plain text, the cipher text
     */
    encrypt(X, twk) {
        return this.cipher(X, twk, true);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF3_1 object.
     *
     * @param X   the cipher text to be decrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the decryption of the cipher text, the plain text
     */
    decrypter(X, twk) {
        return this.cipher(X, twk, false);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF3_1 object.
     *
     * @param X   the cipher text to be decrypted
     *
     * @return    the decryption of the cipher text, the plain text
     */
    decrypt(X) {
        return this.decrypter(X, null);
    }

    BigIntToByteArray(bn) {
        let hex = bn.toString(16);
        if (hex.length % 2) {
            hex = `0${hex}`;
        }
        const len = hex.length / 2;
        const u8 = new Uint8Array(len);

        let i = 0;
        let j = 0;
        while (i < len) {
            u8[i] = parseInt(`${hex[j]}${hex[j + 1]}`, 16);
            i += 1;
            j += 2;
        }
        return u8;
    }

    ByteArrayToBigInt(buf) {
        const hex = [];
        const u8 = this.Uint8Array.from(buf);

        u8.forEach((i) => {
            let h = i.toString(16);
            if (h.length % 2) { h = `0${h}`; }
            hex.push(h);
        });
        return bigInt(`0x${hex.join('')}`);
    }
}

// module.exports = FFX;
