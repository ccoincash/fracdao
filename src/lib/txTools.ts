// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import btc = require('bitcore-lib-inquisition')
import * as ecurve from 'ecurve'
import { sha256 } from 'js-sha256'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import BigInteger = require('bigi')
import {
    ContractTransaction,
    int2ByteString,
    toByteString,
    toHex,
} from 'scrypt-ts'
import { TxOutpoint } from '../contracts/utils/txUtil'
import { SHPreimage } from '../contracts/utils/sigHashUtils'
import { emptyFixedArray } from './proof'

const curve = ecurve.getCurveByName('secp256k1')

function hashSHA256(buff: Buffer | string) {
    return Buffer.from(sha256.create().update(buff).array())
}

export function getSigHashSchnorr(
    transaction: btc.Transaction,
    tapleafHash: Buffer,
    inputIndex = 0,
    sigHashType = 0x00
): {
    preimage: Buffer
    hash: Buffer
} {
    //const sighash = btc.Transaction.Sighash.sighash(transaction, sigHashType, inputIndex, subscript);
    const execdata = {
        annexPresent: false,
        annexInit: true,
        tapleafHash: tapleafHash,
        tapleafHashInit: true,
        ////validationWeightLeft: 110,
        ////validationWeightLeftInit: true,
        codeseparatorPos: new btc.crypto.BN(4294967295),
        codeseparatorPosInit: true,
    }

    return {
        preimage: btc.Transaction.SighashSchnorr.sighashPreimage(
            transaction,
            sigHashType,
            inputIndex,
            3,
            execdata
        ),
        hash: btc.Transaction.SighashSchnorr.sighash(
            transaction,
            sigHashType,
            inputIndex,
            3,
            execdata
        ),
    }
}

export function getE(sighash: Buffer) {
    const Gx = curve.G.affineX.toBuffer(32)

    const tagHash = hashSHA256('BIP0340/challenge')
    const tagHashMsg = Buffer.concat([Gx, Gx, sighash])
    const taggedHash = hashSHA256(Buffer.concat([tagHash, tagHash, tagHashMsg]))

    return BigInteger.fromBuffer(taggedHash).mod(curve.n)
}

export function splitSighashPreimage(preimage: Buffer) {
    return {
        tapSighash1: preimage.subarray(0, 32),
        tapSighash2: preimage.subarray(32, 64),
        epoch: preimage.subarray(64, 65),
        sighashType: preimage.subarray(65, 66),
        txVersion: preimage.subarray(66, 70),
        nLockTime: preimage.subarray(70, 74),
        hashPrevouts: preimage.subarray(74, 106),
        hashSpentAmounts: preimage.subarray(106, 138),
        hashScripts: preimage.subarray(138, 170),
        hashSequences: preimage.subarray(170, 202),
        hashOutputs: preimage.subarray(202, 234),
        spendType: preimage.subarray(234, 235),
        inputNumber: preimage.subarray(235, 239),
        tapleafHash: preimage.subarray(239, 271),
        keyVersion: preimage.subarray(271, 272),
        codeseparatorPosition: preimage.subarray(272),
    }
}

export function toSHPreimageObj(preimageParts, _e, eLastByte): SHPreimage {
    return {
        txVer: toHex(preimageParts.txVersion),
        nLockTime: toHex(preimageParts.nLockTime),
        hashPrevouts: toHex(preimageParts.hashPrevouts),
        hashSpentAmounts: toHex(preimageParts.hashSpentAmounts),
        hashSpentScripts: toHex(preimageParts.hashScripts),
        hashSequences: toHex(preimageParts.hashSequences),
        hashOutputs: toHex(preimageParts.hashOutputs),
        spendType: toHex(preimageParts.spendType),
        inputNumber: toHex(preimageParts.inputNumber),
        hashTapLeaf: toHex(preimageParts.tapleafHash),
        keyVer: toHex(preimageParts.keyVersion),
        codeSeparator: toHex(preimageParts.codeseparatorPosition),
        _e: toHex(_e),
        eLastByte: BigInt(eLastByte),
    }
}

export const getPrevouts = function (tx: btc.Transaction) {
    const lst = emptyFixedArray()
    for (let i = 0; i < tx.inputs.length; i++) {
        const input = tx.inputs[i]
        const txid = input.prevTxId.toString('hex')
        const txhash = Buffer.from(txid, 'hex').reverse()
        const outputBuf = Buffer.alloc(4, 0)
        outputBuf.writeUInt32LE(input.outputIndex)
        lst[i] = Buffer.concat([txhash, outputBuf]).toString('hex')
    }
    return lst
}

export const getPrevoutsIndex = function (tx: btc.Transaction) {
    const lst = emptyFixedArray()
    for (let i = 0; i < tx.inputs.length; i++) {
        const input = tx.inputs[i]
        const outputBuf = Buffer.alloc(4, 0)
        outputBuf.writeUInt32LE(input.outputIndex)
        lst[i] = outputBuf.toString('hex')
    }
    return lst
}

export const getSpentScripts = function (tx: btc.Transaction) {
    const lst = emptyFixedArray()
    for (let i = 0; i < tx.inputs.length; i++) {
        const input = tx.inputs[i]
        const spentScript = input.output.script.toBuffer().toString('hex')
        lst[i] = spentScript
    }
    return lst
}

export const getOutpointObj = function (tx: btc.Transaction, index: number) {
    const outputBuf = Buffer.alloc(4, 0)
    outputBuf.writeUInt32LE(index)
    return {
        txhash: Buffer.from(tx.id, 'hex').reverse().toString('hex'),
        outputIndexBytes: outputBuf.toString('hex'),
    }
}

export const getOutpointString = function (tx: btc.Transaction, index: number) {
    const outputBuf = Buffer.alloc(4, 0)
    outputBuf.writeUInt32LE(index)
    return (
        Buffer.from(tx.id, 'hex').reverse().toString('hex') +
        outputBuf.toString('hex')
    )
}

export const checkDisableOpCode = function (scriptPubKey) {
    for (const chunk of scriptPubKey.chunks) {
        // New opcodes will be listed here. May use a different sigversion to modify existing opcodes.
        if (btc.Opcode.isOpSuccess(chunk.opcodenum)) {
            console.log(chunk.opcodenum, btc.Opcode.reverseMap[chunk.opcodenum])
            return true
        }
    }
    return false
}

export const callToBufferList = function (ct: ContractTransaction) {
    const callArgs = ct.tx.inputs[ct.atInputIndex].script.chunks.map(
        (value) => {
            if (!value.buf) {
                if (value.opcodenum >= 81 && value.opcodenum <= 96) {
                    const hex = int2ByteString(BigInt(value.opcodenum - 80))
                    return Buffer.from(hex, 'hex')
                } else {
                    return Buffer.from(toByteString(''))
                }
            }
            return value.buf
        }
    )
    return callArgs
}

export function getSHPreimage(
    tx,
    inputIndex,
    scriptBuffer
): {
    SHPreimageObj: SHPreimage
    sighash: {
        preimage: Buffer
        hash: Buffer
    }
} {
    let e, eBuff, sighash
    let eLastByte = -1
    // eslint-disable-next-line no-constant-condition
    while (true) {
        sighash = getSigHashSchnorr(tx, scriptBuffer, inputIndex)
        e = getE(sighash.hash)
        eBuff = e.toBuffer(32)
        const lastByte = eBuff[eBuff.length - 1]
        if (lastByte < 127) {
            eLastByte = lastByte
            break
        }
        tx.nLockTime += 1
    }

    if (eLastByte < 0) {
        throw new Error('No valid eLastByte!')
    }

    const _e = eBuff.slice(0, eBuff.length - 1) // e' - e without last byte
    const preimageParts = splitSighashPreimage(sighash.preimage)
    return {
        SHPreimageObj: toSHPreimageObj(preimageParts, _e, eLastByte),
        sighash: sighash,
    }
}

export function getTxCtx(tx, inputIndex, scriptBuffer) {
    const { SHPreimageObj, sighash } = getSHPreimage(
        tx,
        inputIndex,
        scriptBuffer
    )
    const prevouts = getPrevouts(tx)
    const spentScripts = getSpentScripts(tx)
    const outputBuf = Buffer.alloc(4, 0)
    outputBuf.writeUInt32LE(tx.inputs[inputIndex].outputIndex)
    const prevoutsCtx = {
        prevouts: prevouts,
        inputIndex: BigInt(inputIndex),
        outputIndex: BigInt(tx.inputs[inputIndex].outputIndex),
        preTxhash: Buffer.from(
            tx.inputs[inputIndex].prevTxId.toString('hex'),
            'hex'
        )
            .reverse()
            .toString('hex'),
        preOutputIndexBytes: outputBuf.toString('hex'),
    }
    return {
        shPreimage: SHPreimageObj,
        prevoutsCtx: prevoutsCtx,
        spentScripts: spentScripts,
        sighash,
    }
}

export function toTxOutpoint(txid: string, outputIndex: number): TxOutpoint {
    const outputBuf = Buffer.alloc(4, 0)
    outputBuf.writeUInt32LE(outputIndex)
    return {
        txhash: Buffer.from(txid, 'hex').reverse().toString('hex'),
        outputIndexBytes: outputBuf.toString('hex'),
    }
}
