
export enum AddressType {
    LEGACY = 0,
    NATIVE_WITNESS = 1,
    NESTED_WITNESS = 2,
    TAPROOT = 3,
}

export enum DaoOpType {
    STAKE = 0,
    UNSTAKE = 1,
    DELEGATE = 2,
    UNDELEGATE = 3,
    VOTE = 4,
}

// The cool down time for the DAO unstaking
export const LOCK_BLOCK = 1

const VERSION = 0

/**
 * DAO OP_RETURN Data Format
 * PUBKEY_DATA: ADDRESS_TYPE<1 byte> + PUBKEY_PREFIX<1 bytes> + X_ONLY_PUBKEY<32 bytes>
 * STAKE: PUBKEY_DATA + OP_TYPE<1 byte> + VERSION<1 byte> + DAO_SUFFIX<7 byte>
 * UNSTAKE: PUBKEY_DATA + OP_TYPE<1 byte> + VERSION<1 byte> + DAO_SUFFIX<7 byte>
 */
export const DAO_SUFFIX = Buffer.from('FracDao')

export function encodeDaoOpReturnData(
    pubKeyPrefix: Buffer, 
    xOnlyPubKey: Buffer, 
    addressType: AddressType, 
    opType: DaoOpType
): Buffer {
    const data = Buffer.concat([
        Buffer.from([addressType]),
        pubKeyPrefix,
        xOnlyPubKey,
        Buffer.alloc(1, Number(opType)),
        Buffer.alloc(1, VERSION),
        DAO_SUFFIX, 
    ])
    return data
}

export function decodeDaoOpReturn(script: Buffer): any {
    let pos = DAO_SUFFIX.length
    if (script.subarray(script.length - pos).compare(DAO_SUFFIX) !== 0) {
        return
    }

    if (script.length < DAO_SUFFIX.length + 36) {
        return
    }

    pos += 1
    const version = Number(script[script.length - pos])
    pos += 1
    const opType = Number(script[script.length - pos])
    pos += 32
    const xOnlyPubKey = script.subarray(script.length - pos, script.length - pos + 32).toString('hex')
    pos += 1
    const pubKeyPrefix = script.subarray(script.length - pos, script.length - pos + 1).toString('hex')
    pos += 1
    const addressType = Number(script[script.length - pos])

    return {
        version,
        opType,
        xOnlyPubKey,
        pubKeyPrefix,
        addressType
    }
}