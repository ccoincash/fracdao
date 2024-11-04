import BufferReader from 'bitcore-lib-inquisition/lib/encoding/bufferreader'
import {
    FixedArray,
    byteString2Int,
    fill,
    int2ByteString,
    toByteString,
    toHex,
} from 'scrypt-ts'
import * as varuint from 'varuint-bitcoin'
import { MAX_INPUT, MAX_TOKEN_OUTPUT } from '../contracts/utils/txUtil'

const emptyString = toByteString('')

export const emptyFixedArray = function () {
    return fill(emptyString, MAX_INPUT)
}

export const emptyTokenArray = function () {
    return fill(emptyString, MAX_TOKEN_OUTPUT)
}

export const emptyBigIntArray = function () {
    return fill(0n, MAX_INPUT)
}

export const emptyTokenAmountArray = function () {
    return fill(0n, MAX_TOKEN_OUTPUT)
}

export const intArrayToByteString = function (
    array: FixedArray<bigint, typeof MAX_INPUT>
) {
    const rList = emptyFixedArray()
    for (let index = 0; index < array.length; index++) {
        const element = array[index]
        rList[index] = int2ByteString(element)
    }
    return rList
}

export const tokenAmountToByteString = function (
    array: FixedArray<bigint, typeof MAX_TOKEN_OUTPUT>
) {
    const rList = emptyTokenArray()
    for (let index = 0; index < array.length; index++) {
        const element = array[index]
        rList[index] = int2ByteString(element)
    }
    return rList
}

export const txToTxHeader = function (tx) {
    const headerReader = BufferReader(tx.toBuffer(true))
    const version = headerReader.read(4)
    const inputNumber = headerReader.readVarintNum()
    const inputTxhashList = emptyFixedArray()
    const inputOutputIndexBytesList = emptyFixedArray()
    const inputScriptBytesList = emptyFixedArray()
    const inputSequenceList = emptyFixedArray()
    for (let index = 0; index < inputNumber; index++) {
        const txhash = headerReader.read(32)
        const outputIndexBytes = headerReader.read(4)
        const unlockScript = headerReader.readVarLengthBuffer()
        if (unlockScript.length > 0) {
            throw Error(`input ${index} unlocking script need eq 0`)
        }
        const sequence = headerReader.read(4)
        inputTxhashList[index] = toHex(txhash)
        inputOutputIndexBytesList[index] = toHex(outputIndexBytes)
        inputScriptBytesList[index] = toByteString('00')
        inputSequenceList[index] = toHex(sequence)
    }
    const outputNumber = headerReader.readVarintNum()
    const outputSatoshiBytesList = emptyFixedArray()
    const outputScriptLenBytesList = emptyFixedArray()
    const outputScriptList = emptyFixedArray()
    for (let index = 0; index < outputNumber; index++) {
        const satoshiBytes = headerReader.read(8)
        const scriptLen = headerReader.readVarintNum()
        const script = headerReader.read(scriptLen)
        outputSatoshiBytesList[index] = toHex(satoshiBytes)
        outputScriptLenBytesList[index] = toHex(varuint.encode(scriptLen))
        outputScriptList[index] = toHex(script)
    }
    const nLocktime = headerReader.read(4)
    return {
        version: toHex(version),
        inputNumber: toHex(varuint.encode(inputNumber)),
        inputTxhashList: inputTxhashList,
        inputOutputIndexBytesList: inputOutputIndexBytesList,
        inputScriptBytesList: inputScriptBytesList,
        inputSequenceList: inputSequenceList,
        outputNumber: toHex(varuint.encode(outputNumber)),
        outputSatoshiBytesList: outputSatoshiBytesList,
        outputScriptLenBytesList: outputScriptLenBytesList,
        outputScriptList: outputScriptList,
        nLocktime: toHex(nLocktime),
    }
}

export const txToTxHeaderPartial = function (txHeader) {
    const inputs = emptyFixedArray()
    for (let index = 0; index < inputs.length; index++) {
        inputs[index] =
            txHeader.inputTxhashList[index] +
            txHeader.inputOutputIndexBytesList[index] +
            txHeader.inputScriptBytesList[index] +
            txHeader.inputSequenceList[index]
    }
    const outputSatoshiList = emptyFixedArray()
    const outputScriptList = emptyFixedArray()
    for (let index = 0; index < outputSatoshiList.length; index++) {
        outputSatoshiList[index] = txHeader.outputSatoshiBytesList[index]
        outputScriptList[index] = txHeader.outputScriptList[index]
    }
    return {
        version: txHeader.version,
        inputNumberBytes: txHeader.inputNumber,
        inputs: inputs,
        outputNumber: byteString2Int(txHeader.outputNumber),
        outputNumberBytes: txHeader.outputNumber,
        outputSatoshiList: outputSatoshiList,
        outputScriptList: outputScriptList,
        nLocktime: txHeader.nLocktime,
    }
}

export const txToTxHeaderTiny = function (txHeader) {
    let inputString = toByteString('')
    const inputs = emptyFixedArray()
    for (let index = 0; index < inputs.length; index++) {
        // inputs[index] =
        inputString +=
            txHeader.inputTxhashList[index] +
            txHeader.inputOutputIndexBytesList[index] +
            txHeader.inputScriptBytesList[index] +
            txHeader.inputSequenceList[index]
    }
    const prevList = fill(emptyString, 4)
    const _prevList =
        txHeader.version +
        txHeader.inputNumber +
        inputString +
        txHeader.outputNumber
    for (let index = 0; index < 4; index++) {
        const start = index * 80 * 2
        const end = start + 80 * 2
        prevList[index] = _prevList.slice(start, end)
    }
    const outputSatoshiList = emptyFixedArray()
    const outputScriptList = emptyFixedArray()
    for (let index = 0; index < outputSatoshiList.length; index++) {
        outputSatoshiList[index] = txHeader.outputSatoshiBytesList[index]
        outputScriptList[index] = txHeader.outputScriptList[index]
    }
    return {
        preList: prevList,
        outputNumber: byteString2Int(txHeader.outputNumber),
        outputNumberBytes: txHeader.outputNumber,
        outputSatoshiList: outputSatoshiList,
        outputScriptList: outputScriptList,
        nLocktime: txHeader.nLocktime,
    }
}

export const txToTxHeaderCheck = function (txHeader) {
    let inputString = toByteString('')
    const inputs = emptyFixedArray()
    for (let index = 0; index < inputs.length; index++) {
        inputString +=
            txHeader.inputTxhashList[index] +
            txHeader.inputOutputIndexBytesList[index] +
            txHeader.inputScriptBytesList[index] +
            txHeader.inputSequenceList[index]
    }
    const outputSatoshiList = fill(emptyString, 3)
    const outputScriptList = fill(emptyString, 3)
    for (let index = 0; index < outputSatoshiList.length; index++) {
        outputSatoshiList[index] = txHeader.outputSatoshiBytesList[index]
        outputScriptList[index] = txHeader.outputScriptList[index]
    }
    return {
        prev:
            txHeader.version +
            txHeader.inputNumber +
            inputString +
            txHeader.outputNumber,
        outputNumber: byteString2Int(txHeader.outputNumber),
        outputNumberBytes: txHeader.outputNumber,
        outputSatoshiList: outputSatoshiList,
        outputScriptList: outputScriptList,
        nLocktime: txHeader.nLocktime,
    }
}

export const getTxHeaderCheck = function (tx, outputIndex: number) {
    const txHeader = txToTxHeader(tx)
    const outputBuf = Buffer.alloc(4, 0)
    outputBuf.writeUInt32LE(outputIndex)
    return {
        tx: txToTxHeaderCheck(txHeader),
        outputBytes: outputBuf.toString('hex'),
        outputIndex: BigInt(outputIndex),
        outputPre:
            txHeader.outputSatoshiBytesList[outputIndex] +
            txHeader.outputScriptLenBytesList[outputIndex],
    }
}
