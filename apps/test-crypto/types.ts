import { JSON } from '@klave/sdk';

@serializable
export class ErrorMessage {
    success!: boolean;
    message!: string;
}

@serializable
export class FetchInput {
    key!: string;
}

@serializable
export class FetchOutput {
    success!: boolean;
    value!: string;
}

@serializable
export class StoreInput {
    key!: string;
    value!: string;
}

@serializable
export class StoreOutput {
    success!: boolean;
}

@serializable
export class KeyField {
    keyName!: string;
}

@serializable
export class InputEncryption {
    keyName!: string;
    data!: string;
}

@serializable
export class InputDecryption {
    keyName!: string;
    dataEncrypted!: string;
}

@serializable
export class KeyList {
    list!: string[];
}