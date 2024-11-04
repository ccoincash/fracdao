import {
    method,
    toByteString,
    ByteString,
    SmartContractLib,
    FixedArray,
    len,
    int2ByteString,
    prop,
    assert,
} from 'scrypt-ts'
import { SpentScriptsCtx } from './sigHashUtils'

export type int32 = bigint
export const Int32 = BigInt

export type TxOutpoint = {
    txhash: ByteString
    outputIndexBytes: ByteString
}

export type LockingScriptParts = {
    code: ByteString
    data: ByteString
}

export type OpPushData = {
    len: int32
    value: int32
}

export type VarIntData = {
    len: int32
    value: int32
}

export type ChangeInfo = {
    script: ByteString
    satoshisBytes: ByteString
}

/*
Because of bvm stack max element size is 520, witness tx calculate txid data need less than 520.
so max input number is 6, and output number is 6.
version 4
inputNumber 1
input (32 + 4 + 1 + 4) * inputNumber
outputNumber 1
output (8 + 1 + 34(p2tr script size)) * outputNumber
nLocktime 4
(520 - (4 + 1 + 1 + 4)) / (41 + 43) = 6.07
*/
// tx max input number
export const MAX_INPUT = 6
// tx max ouput number
export const MAX_OUTPUT = 6
// tx max token input number
export const MAX_TOKEN_INPUT = 5
// tx max token output number
export const MAX_TOKEN_OUTPUT = 5
// tx max stated output number, same as token output number
export const MAX_STATE = 5
// amount check output number
export const MAX_CHECK_OUTPUT = 3

export class TxUtil extends SmartContractLib {
    @prop()
    static readonly ZEROSAT: ByteString = toByteString('0000000000000000')

    @method()
    static mergePrevouts(
        prevouts: FixedArray<ByteString, typeof MAX_INPUT>
    ): ByteString {
        let result = toByteString('')
        for (let index = 0; index < MAX_INPUT; index++) {
            const prevout = prevouts[index]
            result += prevout
        }
        return result
    }

    @method()
    static mergeSpentScripts(spentScripts: SpentScriptsCtx): ByteString {
        let result = toByteString('')
        for (let index = 0; index < MAX_INPUT; index++) {
            const spentScript = spentScripts[index]
            result += int2ByteString(len(spentScript)) + spentScript
        }
        return result
    }

    @method()
    static buildOutput(
        script: ByteString,
        satoshiBytes: ByteString
    ): ByteString {
        const nlen = len(script)
        assert(nlen <= 34)
        return satoshiBytes + int2ByteString(nlen) + script
    }

    @method()
    static checkIndex(index: int32, indexBytes: ByteString): boolean {
        let indexByte = int2ByteString(index)
        if (indexByte == toByteString('')) {
            indexByte = toByteString('00')
        }
        return indexByte + toByteString('000000') == indexBytes
    }

    @method()
    static buildOpReturnRoot(script: ByteString): ByteString {
        return (
            toByteString('0000000000000000') +
            int2ByteString(len(script)) +
            script
        )
    }

    @method()
    static getStateScript(hashRoot: ByteString): ByteString {
        // op_return + 24 + cat + version(01) + hashroot
        return toByteString('6a1863617401') + hashRoot
    }

    @method()
    static getChangeOutput(changeInfo: ChangeInfo): ByteString {
        return changeInfo.satoshisBytes != TxUtil.ZEROSAT
            ? TxUtil.buildOutput(changeInfo.script, changeInfo.satoshisBytes)
            : toByteString('')
    }
}
