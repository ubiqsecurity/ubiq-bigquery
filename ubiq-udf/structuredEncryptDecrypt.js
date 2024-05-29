// Comments left to show these are required but BigQuery libraries don't use requires/paths.
// const { FF1, Bn } = require('ubiq-security-fpe');

// If true, when ffs is not found, the input will be returned (No Change)
HANDLE_CACHE_MISS = true

class StructuredEncryptDecrypt {
    constructor({ datasetName, ubiqDatasetKeyCache }) {
        if (ubiqDatasetKeyCache[datasetName]) {
            this.cache = ubiqDatasetKeyCache[datasetName]
        } else {
            throw new Error(`Dataset "${datasetName}" not found in cache.`);
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

    FormatInput(str, pth, ics, ocs, rules = []) {
        const strArr = str.split('');
        const setInputChar = new Set(ics.split(''));

        // Add rule for legacy passthrough if no rules present
        if (rules.length == 0 && pth.length > 0) {
            rules.push({ type: "passthrough", value: pth, priority: 1 })
        }

        // Sort by ascending priority
        rules = [...rules.sort((i, j) => {
            if(i.priority > j.priority) return 1;
            if(i.priority > j.priority) return -1;
            return 0
        })];

        let trimText = [...strArr];
        const formattedDestination = [];
        for (const [idx, rule] of rules.entries()) {
            switch (rule.type) {
                case "passthrough":
                    const pthTrim = []
                    const setPassthrough = new Set(rule.value.split(''));

                    for (const currentChar of strArr) {
                        if (setPassthrough.has(currentChar) === false) {
                            pthTrim.push(currentChar);
                            formattedDestination.push(ocs[0]);
                        } else {
                            formattedDestination.push(currentChar);
                        }
                    }
                    trimText = [...pthTrim];
                    // console.log(`passthrough - trimText ${trimText.join('')}`)
                    break;
                case "prefix":
                    rules[idx].buffer = trimText.slice(0, rule.value)
                    trimText = trimText.slice(rule.value)
                    // console.log(`prefix - trimText ${trimText.join('')}`)
                    break;
                case "suffix":
                    rules[idx].buffer = trimText.slice(trimText.length - rule.value)
                    trimText = trimText.slice(0, trimText.length - rule.value)
                    // console.log(`suffix - trimText ${trimText.join('')}`)
                    break;
                default:
                    throw new Error(`Ubiq BigQuery Library does not support rule type "${rule.type}" at this time`)
            }
        }

        if (!trimText.every(c => setInputChar.has(c))) {
            throw new Error(`Invalid input string character(s)`);
        }

        return { formattedDestination, trimText, rules }
    }

    FormatOutput(formattedDestination, inputText, pth, rules) {
        let outputText = [...inputText]
        // Sort by descending priority
        rules = [...rules.sort((i, j) => {
            if(i.priority > j.priority) return -1;
            if(i.priority > j.priority) return 1;
            return 0
        })];
        for (const rule of rules) {
            switch (rule.type) {
                case "passthrough":
                    let k = 0;
                    const setPassthrough = new Set(rule.value.split(''));
                    for (let i = 0; i < formattedDestination.length; i++) {
                        if (setPassthrough.has(formattedDestination[i]) === false) {
                            formattedDestination[i] = outputText[k];
                            k++;
                        }
                    }
                    outputText = [...formattedDestination]
                    break;
                case "prefix":
                    outputText = [...rule.buffer, ...outputText]
                    break;
                case "suffix":
                    outputText = [...outputText, ...rule.buffer]
                    break;
                default:
                    throw new Error(`Ubiq BigQuery Library does not support rule type "${rule.type}" at this time`)
            }
        }

        return outputText
    }


    async EncryptAsync(plainText, tweak) {
        // active key will be used during decryption
        const { ctx, activeKey } = await this.GetFF1(this.ffs, null);

        var x = await this.EncryptAsyncKeyNumber(ctx, this.ffs, plainText, tweak, activeKey);
        return x
    }

    async EncryptAsyncKeyNumber(ctx, ffs, plainText, tweak, keyNumber) {

        const { formattedDestination, trimText, rules } = this.FormatInput(plainText, ffs.passthrough, ffs.input_character_set, ffs.output_character_set, ffs.passthrough_rules);

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

        const finalCipherText = this.FormatOutput(formattedDestination, cipherTextPadArr, ffs.passthrough, rules)

        return finalCipherText.join('');
    }

    async DecryptAsync(cipherText, tweak) {
        const {formattedDestination, trimText: cipherTrimText, rules} = this.FormatInput(cipherText, this.ffs.passthrough, this.ffs.output_character_set, this.ffs.input_character_set, this.ffs.passthrough_rules)

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

        const decryptedPlainText = this.FormatOutput(formattedDestination, plainTextValue, this.ffs.passthrough, rules).join('');
 
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
    try {
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ datasetName, ubiqDatasetKeyCache });
    } catch (ex) {
        // Return unencrypted
        if (HANDLE_CACHE_MISS) {
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
    try {
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ datasetName, ubiqDatasetKeyCache });
    } catch (ex) {
        // Return unencrypted
        if (HANDLE_CACHE_MISS) {
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
    catch (ex) {
        return `${ex} ${ex.stack}`
    } finally {
        // await ubiqEncryptDecrypt.close();
    }
    return cipherText;
}

async function EncryptForSearch({ plainText, datasetName, ubiqDatasetKeyCache }) {
    var ubiqEncryptDecrypt;
    try {
        ubiqEncryptDecrypt = new StructuredEncryptDecrypt({ datasetName, ubiqDatasetKeyCache });
    } catch (ex) {
        // Return unencrypted
        if (HANDLE_CACHE_MISS) {
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
