import { Notifier, Crypto, Ledger, JSON } from '@klave/sdk';
import { FetchInput, FetchOutput, StoreInput, StoreOutput, ErrorMessage, InputDecryption, InputEncryption, KeyField, KeyList } from './types';
import { encode } from 'as-base64/assembly'
import { convertToUint8Array } from './utils';

const myTableName = "my_storage_table";
const publicKeyTable = 'publicKeyTable';
const aesKeyTable = 'aesKeyTable';

/**
 * @query
 * @param {FetchInput} input - A parsed input argument
 */
export function fetchValue(input: FetchInput): void {

    let value = Ledger.getTable(myTableName).get(input.key);
    if (value.length === 0) {
        Notifier.sendJson<ErrorMessage>({
            success: false,
            message: `key '${input.key}' not found in table`
        });
    } else {
        Notifier.sendJson<FetchOutput>({
            success: true,
            value
        });
    }
}

/**
 * @transaction
 * @param {StoreInput} input - A parsed input argument
 */
export function storeValue(input: StoreInput): void {

    if (input.key && input.value) {
        Ledger.getTable(myTableName).set(input.key, input.value);
        Notifier.sendJson<StoreOutput>({
            success: true
        });
        return;
    }

    Notifier.sendJson<ErrorMessage>({
        success: false,
        message: `Missing value arguments`
    });
}


/**
 * @query
 */
export function displayPublicKeyList(): void {

    let raw = Ledger.getTable(publicKeyTable).get("list");
    if (raw.length === 0)
    {
        Notifier.sendJson<string>("Nothing to display");
        return;
    }
    let obj = JSON.parse<KeyList>(raw);
    Notifier.sendJson<KeyList>(obj);
    return;
}

/**
 * @query
 */
export function displayAesKeyList(): void {

    let raw = Ledger.getTable(aesKeyTable).get("list");
    if (raw.length === 0)
    {
        Notifier.sendJson<string>("Nothing to display");
        return;
    }
    let obj = JSON.parse<KeyList>(raw);
    Notifier.sendJson<KeyList>(obj);
    return;
}

/**
 * @query
 */
export function displayPublicKey(input: KeyField): void {

    let myKeyName = input.keyName;
    let myKey = Crypto.ECDSA.getKey(myKeyName);

    if (myKey == null)
    {
        Notifier.sendJson<string>("Key does not exist");
        return;
    }
    Notifier.sendJson<string>(myKey.getPublicKey().getPem());
    return;
}

/**
 * @query
 */
export function encrypt(input: InputEncryption): void {

    let myKeyName = input.keyName;
    let myKey = Crypto.AES.getKey(myKeyName);

    if (myKey == null)
    {
        Notifier.sendJson<string>("Key does not exist");
        return;
    }

    let myData = input.data;
    Notifier.sendJson<string>(encode(convertToUint8Array(myKey.encrypt(myData))));
    return;
}

/**
 * @query
 */
export function decrypt(input: InputDecryption): void {

    let myKeyName = input.keyName;
    let myKey = Crypto.AES.getKey(myKeyName);

    if (myKey == null)
    {
        Notifier.sendJson<string>("Key does not exist");
        return;
    }

    let myData = input.dataEncrypted;
    Notifier.sendJson<string>(encode(convertToUint8Array(myKey.encrypt(myData))));
    return;
}