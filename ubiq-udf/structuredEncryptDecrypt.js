// Comments left to show these are required but BigQuery libraries don't use requires/paths.
// const { FF1, Bn } = require('ubiq-security-fpe');

HANDLE_CACHE_MISS = true

class StructuredEncryptDecrypt {
    constructor({ datasetName, ubiqDatasetKeyCache }) {
        if (ubiqDatasetKeyCache[datasetName]) {
            this.cache = ubiqDatasetKeyCache[datasetName]
        } else {
            throw `Dataset "${datasetName}" not found in cache.`
        }
        this.ffs = this.cache['ffs']
    }

    // eslint doesn't like a "return await" so just to be sure, perform in two stpes
    async close() {
        // Close billing info (maybe not BigQuery supported)        
    }

    EncodeKeyNum(ffs, keyNumber, str, position) {
        if (position < 0) {
            throw new Error(`Bad String decoding position for: ${str}`);
        }
        const strChars = str.split('');
        const charBuf = strChars[position];

        let ct_value = ffs.OutputCharacters.indexOf(charBuf);
        const msb_encoding_bits = ffs.MsbEncodingBits;

        ct_value += (keyNumber << msb_encoding_bits.Value);

        const ch = ffs.OutputCharacters.subString(ct_value, 1);
        strChars[position] = ch[0];
        return String(strChars);
    }

    async GetFF1(ffs, keyNumber) {
        const unwrapped_data_key = this.cache.keys[this.cache.current_key_number]
        const activeKey = this.cache.current_key_number

        return this.AddFF1(ffs, unwrapped_data_key, keyNumber, activeKey);
    }

    // Add to the cache.  Key number may not always be the same as active key.
    AddFF1(ffs, unwrapped_data_key, activeKey) {
        const tweakUint8 = Base64Binary.decode(ffs.tweak);
        this.keyRaw = Base64Binary.decode(unwrapped_data_key);
        const ctx = new FF1(
            unwrapped_data_key,
            tweakUint8,
            this.tweak_min_len,
            this.tweak_max_len,
            ffs.input_character_set.length,
            ffs.input_character_set,
        );

        return { ctx, activeKey };
    }




    async EncryptAsync(plainText, tweak) {
        // active key will be used during decryption
        const { ctx, activeKey } = await this.GetFF1(this.ffs, null);

        var x = await this.EncryptAsyncKeyNumber(ctx, this.ffs, plainText, tweak, activeKey);
        return x
    }

    async EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, keyNumber) {

        const plainTextArr = plainText.split('');
        const setInputChar = new Set(ffs.input_character_set.split(''));
        const setPassthrough = new Set(ffs.passthrough.split(''));

        const trimText = [];
        const formattedDestination = [];

        // eslint-disable-next-line no-restricted-syntax
        for (const currentChar of plainTextArr) {
            if (setPassthrough.has(currentChar) === false) {
                if (setInputChar.has(currentChar) === false) {
                    throw new Error(`invalid character found in the input:${currentChar}`);
                }
                trimText.push(currentChar);
                formattedDestination.push(ffs.output_character_set[0]);
            } else {
                formattedDestination.push(currentChar);
            }
        }
        if (trimText.length < ffs.min_input_length || trimText.length > ffs.max_input_length) {
            throw new Error(`Invalid input len min: ${ffs.min_input_length} max: ${ffs.max_input_length}`);
        }
        const encrypted = ctx.encrypt(trimText.join(''));
        const bigNum1 = bigint_set_str(encrypted, ffs.input_character_set);
        const cipherText = bigint_get_str(ffs.output_character_set, bigNum1);
        const cipherTextPad = cipherText.padStart(trimText.length, ffs.output_character_set[0]);
        const keyNumIndex = ffs.output_character_set.indexOf(cipherTextPad[0]);
        const ct_value = keyNumIndex + (parseInt(keyNumber, 10) << ffs.msb_encoding_bits);
        const cipherTextPadArr = cipherTextPad.split('');
        cipherTextPadArr[0] = ffs.output_character_set[ct_value];
        let k = 0;
        for (let i = 0; i < formattedDestination.length; i++) {
            if (formattedDestination[i] === ffs.output_character_set[0]) {
                formattedDestination[i] = cipherTextPadArr[k];
                k++;
            }
        }

        return formattedDestination.join('');
    }

    async DecryptAsync(cipherText, tweak) {
        const cipherTextPadArr = cipherText.split('');

        const setOutputChar = new Set(this.ffs.output_character_set.split(''));
        const setPassthrough = new Set(this.ffs.passthrough.split(''));

        const cipherTrimText = [];
        const formattedDestination = [];

        // eslint-disable-next-line no-restricted-syntax
        for (const currentChar of cipherTextPadArr) {
            if (setPassthrough.has(currentChar) === false) {
                if (setOutputChar.has(currentChar) === false) {
                    throw new Error(`Invalid input char:${currentChar}`);
                }
                cipherTrimText.push(currentChar);
                formattedDestination.push(this.ffs.input_character_set[0]);
            } else {
                formattedDestination.push(currentChar);
            }
        }
        let first = this.ffs.output_character_set.indexOf(cipherTrimText[0]);
        const activeKey = first >> this.ffs.msb_encoding_bits;
        first -= (activeKey << this.ffs.msb_encoding_bits);
        cipherTrimText[0] = this.ffs.output_character_set[first];

        // active key will be used during decryption
        const { ctx } = await this.GetFF1(this.ffs, activeKey);

        const bigNum1 = bigint_set_str(
            cipherTrimText.join(''),
            this.ffs.output_character_set,
        );
        const plainText = bigint_get_str(this.ffs.input_character_set, bigNum1);
        const plainTextPad = plainText.padStart(
            cipherTrimText.length,
            this.ffs.input_character_set[0],
        );
        const plainTextValue = ctx.decrypt(plainTextPad);
        let k = 0;
        for (let i = 0; i < formattedDestination.length; i++) {
            if (formattedDestination[i] === this.ffs.input_character_set[0]) {
                formattedDestination[i] = plainTextValue[k];
                k++;
            }
        }
        const decryptedPlainText = formattedDestination.join('');

        return decryptedPlainText;
    }

    async EncryptForSearchAsync(plainText, tweak) {
        var keys = this.cache.keys
        var ct = []
        for (let i = 0; i < keys.length; i++) {
            const { ctx, key } = await this.AddFF1(this.ffs, this.cache.keys[i], i);
            
            ct.push(await this.EncryptAsyncKeyNumber(ctx, this.ffs, plainText, tweak, i))
        }

        return ct
    }
}

async function Decrypt({ cipherText, datasetName, ubiqDatasetKeyCache }) {
    var ubiqEncryptDecrypt;
    try{
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({datasetName, ubiqDatasetKeyCache});
    } catch (ex){
        // Return unencrypted
        if(HANDLE_CACHE_MISS){
            return cipherText
        } else {
            return `${ex} ${ex.stack}`
        }
    }
    const tweakFF1 = [];

    try {

        var plainText = await ubiqEncryptDecrypt.DecryptAsync(
            cipherText,
            tweakFF1,
        );
    } catch (ex) {
        throw ex
    } finally {
        await ubiqEncryptDecrypt.close();
    }
    return plainText;
}

async function Encrypt({ plainText, datasetName, ubiqDatasetKeyCache }) {
    var ubiqEncryptDecrypt;
    try{
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({datasetName, ubiqDatasetKeyCache});
    } catch (ex){
        // Return unencrypted
        if(HANDLE_CACHE_MISS){
            return plainText
        } else {
            return `${ex} ${ex.stack}`
        }
    }
    const tweakFF1 = [];
    try {
        var cipherText = await ubiqEncryptDecrypt.EncryptAsync(
            plainText,
            tweakFF1
        );
    }
    catch (ex){
        return `${ex} ${ex.stack}`
    } finally {
        // await ubiqEncryptDecrypt.close();
    }
    return cipherText;
}

async function EncryptForSearch({plainText, datasetName, ubiqDatasetKeyCache}) {
    var ubiqEncryptDecrypt;
    try{
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({datasetName, ubiqDatasetKeyCache});
    } catch (ex){
        // Return unencrypted
        if(HANDLE_CACHE_MISS){
            return plainText
        } else {
            return `${ex} ${ex.stack}`
        }
    }
    const tweakFF1 = [];
    try {
        var cipherText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
            plainText,
            tweakFF1
        );
    }
    catch (ex) {
        throw ex
    } finally {
        await ubiqEncryptDecrypt.close();
    }

    return cipherText;
}


// module.exports = {
//     StructuredEncryptDecrypt,
//     Decrypt,
//     Encrypt,
//     EncryptForSearch
// };
