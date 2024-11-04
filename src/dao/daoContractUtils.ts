import { bech32m } from 'bech32'
import { Tap } from '@cmdcode/tapscript' // Requires node >= 19
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import btc = require('bitcore-lib-inquisition')
import {
    getDummyUTXO,
    getDummySigner,
} from '../../tests/utils/txHelper'
import {
  callToBufferList,
  getTxCtx,
} from '../lib/txTools'
import { MethodCallOptions, toByteString } from 'scrypt-ts'
import { Stake } from '../contracts/dao/stake'
import { DaoOpType, AddressType, encodeDaoOpReturnData, LOCK_BLOCK } from './daoProto'
import * as bitcoin from 'bitcoinjs-lib'
import * as secp256k1 from 'tiny-secp256k1'
import ECPairFactory from 'ecpair'
const ECPair = ECPairFactory(secp256k1)

export const TAPROOT_ONLY_SCRIPT_PUBKEY = Buffer.from('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex')

export function toXOnly(pubkey: Buffer): Buffer {
  return pubkey.subarray(1, 33)
}

export function taprootAddressString2Hex(address: string) {
  const decoded = bech32m.decode(address)
  const addressHex = Buffer.from(bech32m.fromWords(decoded.words.slice(1)))
  return addressHex.toString('hex')
}

export function taprootAddressHex2String(addressHex: string) {
  const data = Buffer.from(addressHex, 'hex');

  const words = bech32m.toWords(data);

  const taprootWords = [0x01, ...words];

  const taprootAddress = bech32m.encode('bc', taprootWords);
  return taprootAddress
}

function getPsbtFromRawTx(jsonData, network: bitcoin.Network = bitcoin.networks.bitcoin) {

  // Step 2: Create a new PSBT object
  const psbt = new bitcoin.Psbt({ network });

  // Step 3: Add the inputs and outputs from the raw transaction to the PSBT

  // Add inputs
  for (let i = 0; i < jsonData.inputs.length; i++) {
    const input = jsonData.inputs[i]
    psbt.addInput({
      hash: input.prevTxId,
      index: input.outputIndex,
      witnessUtxo: {
        script: Buffer.from(input.output.script, 'hex'),
        value: input.output.satoshis,
      },
      tapLeafScript: input.tapLeafScript
    });
  }

  // Add outputs
  for (const output of jsonData.outputs) {
    psbt.addOutput({
      script: Buffer.from(output.script, 'hex'),
      value: output.satoshis
    });
  }

  return psbt
}

export function getTimeLockScript(xOnlyPubKey: Buffer) {
  let scriptNum = btc.crypto.BN.fromNumber(LOCK_BLOCK).toScriptNumBuffer()
  if (LOCK_BLOCK <= 16) {
    scriptNum = btc.Opcode.OP_1 + LOCK_BLOCK - 1
  }
  const timeLockScript = new btc.Script()
    .add(scriptNum)
    .add(btc.Opcode.OP_CHECKSEQUENCEVERIFY)
    .add(btc.Opcode.OP_DROP)
    .add(xOnlyPubKey)
    .add(btc.Opcode.OP_CHECKSIG)
    .toBuffer()
  //const timeLockScript = bitcoin.script.fromASM(`${bitcoin.script.number.encode(LOCK_BLOCK).toString('hex')} OP_CHECKSEQUENCEVERIFY OP_DROP ${xOnlyPubKey.toString('hex')} OP_CHECKSIG`);

  const tapLeaf = Tap.encodeScript(
    timeLockScript
  )
  const [taprootPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: tapLeaf,
    }
  )

  const outputScript = new btc.Script(`OP_1 32 0x${taprootPubKey}`).toBuffer()
  return { address: taprootPubKey, outputScript, lockingScript: timeLockScript, cblock, tapLeaf }
}

// build a stake contract
export function buildStake(publicKey: Buffer, addressType: AddressType) {
  Stake.loadArtifact()

  let xOnlyPubKey = toXOnly(publicKey)

  const { outputScript } = getTimeLockScript(xOnlyPubKey)

  // realPubKey is a 33 bytes buffer. since the length of taproot pubkey is 32 bytes, we need to add a 0x00 prefix
  let pubKeyPrefix = publicKey.subarray(0, 1)
  if (addressType == AddressType.TAPROOT) {
    pubKeyPrefix = Buffer.alloc(1, 0)
  }

  const unStakeOpReturnData = encodeDaoOpReturnData(pubKeyPrefix, xOnlyPubKey, addressType, DaoOpType.UNSTAKE)
  const opReturnScript = btc.Script.buildDataOut(unStakeOpReturnData).toBuffer()
  const stake = new Stake(outputScript.toString('hex'), xOnlyPubKey.toString('hex'), opReturnScript.toString('hex'))

  const stakeOpReturnData = encodeDaoOpReturnData(pubKeyPrefix, xOnlyPubKey, addressType, DaoOpType.STAKE)
  const stakeOpreturnScript = btc.Script.buildDataOut(stakeOpReturnData).toBuffer()

  const [tPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: Tap.encodeScript(stake.lockingScript.toBuffer())
    }
  )

  const stakeAsm = stake.lockingScript.toString()
  console.log('stakeAsm', stakeAsm)

  const stakeOutputScript = new btc.Script(`OP_1 32 0x${tPubKey}`).toBuffer()

  console.log('buildStake: Stake taproot address', tPubKey, cblock)
  return { address: tPubKey, stake, opReturnScript: stakeOpreturnScript, stakeOutputScript, unstakeOpReturnScript: opReturnScript }
}

export async function unlockStake2(
  txid: string, 
  vout: number, 
  inputSatoshis: number, 
  stake, 
  secKey: btc.PrivateKey, 
  stakeOutputTaprootAddress: string, 
  unlockAmount: number, 
  fee: number,
  addressType=AddressType.TAPROOT
) {
  const stakeOutputTaprootScript = new btc.Script(
    `OP_1 32 0x${stakeOutputTaprootAddress}`
  ) 
  console.log('Stake Output Script:', stakeOutputTaprootScript.toString('hex'), stakeOutputTaprootAddress)
  if (unlockAmount < fee) {
    throw new Error('Insufficient funds')
  }

  const remainningAmount = inputSatoshis - unlockAmount
  const withdrawAmount = unlockAmount - fee
  const remainningAmountBytes = Buffer.alloc(8)
  remainningAmountBytes.writeBigUInt64LE(BigInt(remainningAmount), 0)
  const withdrawAmountByte = Buffer.alloc(8)
  withdrawAmountByte.writeBigUInt64LE(BigInt(withdrawAmount), 0)

  const pubkey = secKey.publicKey
  const xOnlyPubKey = pubkey.toBuffer().slice(1, 33)

  const tx1 = new btc.Transaction()
    .from({
      txId: txid,
      outputIndex: vout,
      script: new btc.Script.fromBuffer(stakeOutputTaprootScript.toBuffer()),
      satoshis: inputSatoshis
    })

  // opreturn output
  let pubKeyPrefix = secKey.publicKey.toBuffer().subarray(0, 1)
  if (addressType == AddressType.TAPROOT) {
    pubKeyPrefix = Buffer.alloc(1, 0)
  }
  const opReturnData = encodeDaoOpReturnData(pubKeyPrefix, xOnlyPubKey, addressType, DaoOpType.UNSTAKE)
  const opReturnScript = btc.Script.buildDataOut(opReturnData).toBuffer()
  tx1.addOutput(new btc.Transaction.Output({
    script: opReturnScript,
    satoshis: 0
  }))

  // add timelock output
  const { outputScript } = getTimeLockScript(xOnlyPubKey)  
  tx1.addOutput(new btc.Transaction.Output({
    script: outputScript,
    satoshis: withdrawAmount
  }))

  // stake output 
  const tapLeaf = Tap.encodeScript(
      stake.lockingScript.toBuffer()
  )
  const [taprootPubKey, cblock] = Tap.getPubKey(
      TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
      {
          target: tapLeaf,
      }
  )
  console.log('unlockStake: Taproot pubkey', taprootPubKey, cblock)
  const stakeOutput = btc.Script(`OP_1 32 0x${taprootPubKey}`)
  if (remainningAmount > 0) {
    tx1.addOutput(new btc.Transaction.Output({
      script: stakeOutput,
      satoshis: remainningAmount
    }))
  }

  const { shPreimage, sighash } = getTxCtx(tx1, 0, Buffer.from(tapLeaf, 'hex'))
  console.log('sighash', sighash.hash.toString('hex'))
  //const sig = keyPair.signSchnorr(sighash.hash)

  const keyPair = ECPair.fromWIF(secKey.toWIF(), bitcoin.networks.bitcoin);

  const redeemScript = stake.lockingScript.toBuffer()
  const tapLeaf2 = {
    output: redeemScript,
    version: 192
  };
  const tapTree = tapLeaf2

  const scriptPayment = bitcoin.payments.p2tr({
    // TODO: no G?
    internalPubkey: TAPROOT_ONLY_SCRIPT_PUBKEY,
    scriptTree: tapTree,
    redeem: { output: redeemScript },
    network: bitcoin.networks.bitcoin
  });
  const tapLeafScript = [
    {
      leafVersion: 192,
      script: tapLeaf2.output,
      controlBlock: scriptPayment.witness![scriptPayment.witness!.length - 1]
    }
  ];
  const jsonData = tx1.toJSON()
  jsonData.inputs[0].tapLeafScript = tapLeafScript
  const psbt = getPsbtFromRawTx(jsonData)
  psbt.signInput(0, keyPair)
  psbt.finalizeAllInputs()
  const sig = psbt.extractTransaction().ins[0].witness[0]

  await stake.connect(getDummySigner())
  const stakeCall = await stake.methods.unstake(
    shPreimage,
    () => sig.toString('hex'),
    toByteString(stakeOutputTaprootScript.toBuffer().toString('hex')),
    toByteString(remainningAmountBytes.toString('hex')),
    toByteString(withdrawAmountByte.toString('hex')),
    {
        fromUTXO: getDummyUTXO(inputSatoshis),
        verify: false,
        exec: false, // set true to debug
    } as MethodCallOptions<Stake>
  )
  const callArgs = callToBufferList(stakeCall)
  const witnesses = [
    ...callArgs,
    stake.lockingScript.toBuffer(),
    Buffer.from(cblock, 'hex'),
  ]
  tx1.inputs[0].witnesses = witnesses

  return tx1
}

export async function unlockStake(
  txid: string, 
  vout: number, 
  inputSatoshis: number, 
  stake, 
  secKey: btc.PrivateKey, 
  stakeOutputTaprootAddress: string, 
  unlockAmount: number, 
  fee: number,
  addressType=AddressType.TAPROOT
) {
  const stakeOutputTaprootScript = new btc.Script(
    `OP_1 32 0x${stakeOutputTaprootAddress}`
  ) 
  console.log('Stake Output Script:', stakeOutputTaprootScript.toString('hex'), stakeOutputTaprootAddress)
  if (unlockAmount < fee) {
    throw new Error('Insufficient funds')
  }

  const remainningAmount = inputSatoshis - unlockAmount
  const withdrawAmount = unlockAmount - fee
  const remainningAmountBytes = Buffer.alloc(8)
  remainningAmountBytes.writeBigUInt64LE(BigInt(remainningAmount), 0)
  const withdrawAmountByte = Buffer.alloc(8)
  withdrawAmountByte.writeBigUInt64LE(BigInt(withdrawAmount), 0)

  const pubkey = secKey.publicKey
  const xOnlyPubKey = pubkey.toBuffer().slice(1, 33)

  const tx1 = new btc.Transaction()
    .from({
      txId: txid,
      outputIndex: vout,
      script: new btc.Script.fromBuffer(stakeOutputTaprootScript.toBuffer()),
      satoshis: inputSatoshis
    })

  // opreturn output
  let pubKeyPrefix = secKey.publicKey.toBuffer().subarray(0, 1)
  if (addressType == AddressType.TAPROOT) {
    pubKeyPrefix = Buffer.alloc(1, 0)
  }
  const opReturnData = encodeDaoOpReturnData(pubKeyPrefix, xOnlyPubKey, addressType, DaoOpType.UNSTAKE)
  const opReturnScript = btc.Script.buildDataOut(opReturnData).toBuffer()
  tx1.addOutput(new btc.Transaction.Output({
    script: opReturnScript,
    satoshis: 0
  }))

  // add timelock output
  const { outputScript } = getTimeLockScript(xOnlyPubKey)  
  tx1.addOutput(new btc.Transaction.Output({
    script: outputScript,
    satoshis: withdrawAmount
  }))

  // stake output 
  const tapLeaf = Tap.encodeScript(
      stake.lockingScript.toBuffer()
  )
  const [taprootPubKey, cblock] = Tap.getPubKey(
      TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
      {
          target: tapLeaf,
      }
  )
  console.log('unlockStake: Taproot pubkey', taprootPubKey, cblock)
  const stakeOutput = btc.Script(`OP_1 32 0x${taprootPubKey}`)
  if (remainningAmount > 0) {
    tx1.addOutput(new btc.Transaction.Output({
      script: stakeOutput,
      satoshis: remainningAmount
    }))
  }

  const { shPreimage, sighash } = getTxCtx(tx1, 0, Buffer.from(tapLeaf, 'hex'))

  const sig = btc.crypto.Schnorr.sign(secKey, sighash.hash)

  await stake.connect(getDummySigner())
  const stakeCall = await stake.methods.unstake(
    shPreimage,
    () => sig.toString('hex'),
    toByteString(stakeOutputTaprootScript.toBuffer().toString('hex')),
    toByteString(remainningAmountBytes.toString('hex')),
    toByteString(withdrawAmountByte.toString('hex')),
    {
        fromUTXO: getDummyUTXO(inputSatoshis),
        verify: false,
        exec: false, // set true to debug
    } as MethodCallOptions<Stake>
  )
  const callArgs = callToBufferList(stakeCall)
  const witnesses = [
    ...callArgs,
    stake.lockingScript.toBuffer(),
    Buffer.from(cblock, 'hex'),
  ]
  tx1.inputs[0].witnesses = witnesses

  return tx1
}

export function unlockTimeLock(txid, vout, inputSatoshis, secKey, addressType: AddressType, fee: number) {

  const publicKey = secKey.publicKey
  const xOnlyPubKey = toXOnly(publicKey.toBuffer())
  const { lockingScript, outputScript, cblock, tapLeaf } = getTimeLockScript(xOnlyPubKey)

  const tx = new btc.Transaction().from({
    txId: txid,
    outputIndex: vout,
    script: new btc.Script.fromBuffer(outputScript),
    satoshis: inputSatoshis,
  })
  tx.inputs[0].sequenceNumber = LOCK_BLOCK

  //const address = getAddress(publicKey.toBuffer(), addressType)
  const address = secKey.toAddress()

  tx.addOutput(new btc.Transaction.Output({
    script: new btc.Script(address),
    satoshis: inputSatoshis - fee 
  }))

  const { sighash } = getTxCtx(tx, 0, Buffer.from(tapLeaf, 'hex'))

  const sig = btc.crypto.Schnorr.sign(secKey, sighash.hash)

  const witnesses = [
    sig,
    lockingScript,
    Buffer.from(cblock, 'hex')
  ]

  tx.inputs[0].witnesses = witnesses
  tx.version = 2 // Version 2 is required for OP_CHECKSEQUENCEVERIFY*/

  return tx
}

/*export function unlockTimeLock(txid, vout, inputSatoshis, keyPair, addressType: AddressType, fee: number) {

  const xOnlyPubKey = toXOnly(keyPair.publicKey)
  const { lockingScript } = getTimeLockScript(xOnlyPubKey)

  const redeem = {
    output: lockingScript,
    redeemVersion: 192
  }

  const scriptTree = {
    output: lockingScript,
  }

  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: TAPROOT_ONLY_SCRIPT_PUBKEY,
    scriptTree,
    redeem: redeem,
    network
  });

  const psbt = new bitcoin.Psbt({ network });
  psbt.setVersion(2) // Version 2 is required for OP_CHECKSEQUENCEVERIFY
  psbt.addInput({
      hash: txid,
      index: vout,
      witnessUtxo: { value: inputSatoshis, script: p2tr.output! },
      tapLeafScript: [
          {
              leafVersion: redeem.redeemVersion,
              script: redeem.output,
              controlBlock: p2tr.witness![p2tr.witness!.length - 1] // extract control block from witness data
          }
      ],
      sequence: LOCK_BLOCK
  });

  // generate Taproot address
  const address = getAddress(keyPair.publicKey, addressType)

  psbt.addOutput({
    address: address,
    value: inputSatoshis - fee,
  })

  psbt.signInput(0, keyPair);
  psbt.finalizeAllInputs();
  let tx = psbt.extractTransaction();

  return tx
}*/