import { bech32m } from 'bech32'
import { Tap } from '@cmdcode/tapscript' // Requires node >= 19
import varuint from 'varuint-bitcoin'
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
import { Vote } from '../contracts/dao/vote'
import { DaoOpType, AddressType, encodeDaoOpReturnData, LOCK_BLOCK } from './daoProto'
import { getUInt64Buf, MerkleTreeData } from './voteMerkleTree'
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

// build a vote contract
export function buildVote(proposalId: Buffer, merkleRoot: Buffer) {
  Vote.loadArtifact()

  const vote = new Vote(merkleRoot.toString('hex'), proposalId.toString('hex'))

  const [tPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: Tap.encodeScript(vote.lockingScript.toBuffer())
    }
  )

  const voteOutputScript = new btc.Script(`OP_1 32 0x${tPubKey}`).toBuffer()

  console.log('buildVote: Vote taproot address', tPubKey, cblock)
  return { address: tPubKey, vote, voteOutputScript }
}

export function getAddressFromPublicKey(pubKey: btc.PublickKey, network: string, addressType: AddressType) {
  let at = btc.Address.PayToTaproot
  if (addressType == AddressType.LEGACY) {
    at = btc.Address.PayToPubKeyHash
  } else if (addressType == AddressType.NATIVE_WITNESS) {
    at = btc.Address.PayToWitnessPublicKeyHash
  } else if (addressType == AddressType.NESTED_WITNESS) {
    at = btc.Address.PayToWitnessScriptHash
  }
  return btc.Address.fromPublicKey(pubKey, network, at)
}

export async function unlockVote(
  txid: string, 
  vout: number, 
  inputSatoshis: number, 
  feeUtxo: any,
  vote, 
  secKey: btc.PrivateKey, 
  voteOutputTaprootAddress: string, 
  addressType,
  feePerByte: number,
  voteMerkleTree: MerkleTreeData,
) {
  const voteOutputTaprootScript = new btc.Script(
    `OP_1 32 0x${voteOutputTaprootAddress}`
  ) 
  const tx = new btc.Transaction()
    .from({
      txId: txid,
      outputIndex: vout,
      script: voteOutputTaprootScript,
      satoshis: inputSatoshis,
    })

  // fee tx
  tx.from(feeUtxo)

  const pubKey = secKey.publicKey
  const pubKeyPrefix = pubKey.toBuffer().subarray(0, 1)
  const xOnlyPubKey = toXOnly(pubKey.toBuffer())
  const address = getAddressFromPublicKey(pubKey, 'testnet', addressType)
  const changeAddress = address
  // output
  const opReturnData = encodeDaoOpReturnData(pubKeyPrefix, xOnlyPubKey, addressType, DaoOpType.VOTE)
  const opReturnScript = btc.Script.buildDataOut(opReturnData).toBuffer()
  tx.addOutput(new btc.Transaction.Output({
    script: opReturnScript,
    satoshis: 0
  }))
  tx.feePerByte(feePerByte)
  tx.change(changeAddress)

  const tapLeaf = Tap.encodeScript(vote.lockingScript.toBuffer())
  const [taprootPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: tapLeaf,
    }
  )

  const { shPreimage, sighash } = getTxCtx(tx, 0, Buffer.from(tapLeaf, 'hex'))
  console.log('sighash', sighash.hash.toString('hex'))

  const redeemScript = vote.lockingScript.toBuffer()
  const tapLeaf2 = {
    output: redeemScript,
    version: 192
  };
  const tapTree = tapLeaf2

  const scriptPayment = bitcoin.payments.p2tr({
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
  const txData = tx.toJSON()
  txData.inputs[0].tapLeafScript = tapLeafScript
  const disableTweakSigner = address.type !== btc.Address.PayToTaproot
  const toSignInputs: any[] = []
  for (let i = 0; i < tx.inputs.length; i++) {
      toSignInputs.push({
          index: i,
          address: address.toString(),
          disableTweakSigner
      })
      if (address.type == btc.Address.PayToTaproot) {
          txData.inputs[i].tapInternalKey = toXOnly(pubKey.toBuffer()).toString('hex')
      }
  }
  toSignInputs[0].disableTweakSigner = true
  const psbt = getPsbtFromRawTx(txData)
  const data = {
    psbts: [psbt.toHex()],
    toSignInputs: [toSignInputs],
  }

  const res = signPsbt(data, secKey.toWIF())
  const sigs = extractSigs(res, data.toSignInputs)
  
  const leafKey = Buffer.concat([Buffer.alloc(1, addressType), pubKey.toBuffer()])
  const { neighbor, neighborType, leafNode } = voteMerkleTree.getMerklePath(leafKey)
  const leafData = {
    addressType: Buffer.alloc(1, leafNode.addressType).toString('hex'),
    pubKeyPrefix: Buffer.alloc(1, leafNode.pubKey.subarray(0, 1)).toString('hex'),
    xOnlyPubKey: toXOnly(leafNode.pubKey).toString('hex'),
    stakeSatoshis: getUInt64Buf(leafNode.stakeAmount).toString('hex'),
  }
  const choice = 1
  await vote.connect(getDummySigner())
  const voteCall = await vote.methods.vote(
    choice,
    shPreimage,
    () => sigs[0][0],
    leafData,
    neighbor,
    neighborType,
    {
        fromUTXO: getDummyUTXO(inputSatoshis),
        verify: false,
        exec: true, // set true to debug
    } as MethodCallOptions<Vote>
  )
  const callArgs = callToBufferList(voteCall)
  const witnesses = [
    ...callArgs,
    vote.lockingScript.toBuffer(),
    Buffer.from(cblock, 'hex'),
  ]
  tx.inputs[0].witnesses = witnesses
  if (address.type === btc.Address.PayToWitnessPublicKeyHash) {
    tx.inputs[1].witnesses = [Buffer.from(sigs[0][1], 'hex'), pubKey.toBuffer()]
  } else if (address.type === btc.Address.PayToTaproot) {
    tx.inputs[1].witnesses = [Buffer.from(sigs[0][1], 'hex')]
  } // TODO: PayToPubKeyHash and PayToWitnessScriptHash

  return tx
}

export function serializeScript(s: Buffer): Buffer {
  const varintLen = varuint.encodingLength(s.length);
  const buffer = Buffer.allocUnsafe(varintLen); // better
  varuint.encode(s.length, buffer);
  return Buffer.concat([buffer, s]);
}

export function signPsbt(data: any, wif: string, network = bitcoin.networks.bitcoin) {
  // sign
  const keyPair = ECPair.fromWIF(wif, network);
  const tweakedSigner = keyPair.tweak(
    bitcoin.crypto.taggedHash('TapTweak', toXOnly(keyPair.publicKey)),
  );

  // sign
  const psbts: bitcoin.Psbt[] = []
  for (let i = 0; i < data.psbts!.length; i++) {
    const psbtHex = data.psbts![i]
    const psbt = bitcoin.Psbt.fromHex(psbtHex)
    for (let j = 0; j < data.toSignInputs![i].length; j++) {
      const args = data.toSignInputs![i][j]
      const signer = args.disableTweakSigner === true ? keyPair : tweakedSigner
      const input = psbt.data.inputs[args.index]
      if (input.tapLeafScript) {
        const tapLeaf = psbt.data.inputs[args.index].tapLeafScript![0]
        const hash = bitcoin.crypto.taggedHash(
          'TapLeaf',
          Buffer.concat([Buffer.from([tapLeaf.leafVersion]), serializeScript(tapLeaf.script)]),
        );
        console.debug("signPsbt: sighash %s", hash.toString('hex'))
        psbt.signTaprootInput(args.index, signer, hash)
      } else {
        psbt.signInput(args.index, signer)
      }
    }
    psbts.push(psbt)
  }
  return psbts
}

export function extractSigs(psbts: bitcoin.Psbt[], toSignInputs: any[]) {

  const sigs: string[][] = []
  // extract sigs
  for (let i = 0; i < psbts.length; i++) {
    sigs.push(Array(psbts[i].data.inputs.length).fill(''))
    const psbt = psbts[i]
    for (let j = 0; j < toSignInputs[i].length; j++) {
      const index = toSignInputs[i][j].index
      const input = psbt.data.inputs[index]
      let sig
      if (input.tapLeafScript || input.tapKeySig) {
        sig = input.tapKeySig || input.tapScriptSig![0].signature
      } else {
        sig = input.partialSig![0].signature || Buffer.alloc(0)
      }
      sigs[i][index] = sig.toString('hex')
    }
  }
  return sigs
}

export function createPsbtToSign(tx: btc.Transaction, address: btc.Address, pubKeyBuf: Buffer) {

  // create psbt to sign
  const disableTweakSigner = address.type !== btc.Address.PayToTaproot
  const txData = tx.toJSON()
  const toSignInputs: any[] = []
  for (let i = 0; i < tx.inputs.length; i++) {
      toSignInputs.push({
          index: i,
          address: address.toString(),
          disableTweakSigner
      })
      if (address.type == btc.Address.PayToTaproot) {
          txData.inputs[i].tapInternalKey = toXOnly(pubKeyBuf).toString('hex')
      }
  }
  const psbt = getPsbtFromRawTx(txData)
  return { psbt, toSignInputs }
}

export function getPsbtFromRawTx(jsonData, network: bitcoin.Network = bitcoin.networks.testnet) {

  const psbt = new bitcoin.Psbt({ network });

  psbt.locktime = jsonData.nLockTime
  psbt.version = jsonData.version
  // Add inputs
  for (let i = 0; i < jsonData.inputs.length; i++) {
      const input = jsonData.inputs[i]
      const data: any = {
          hash: input.prevTxId,
          index: input.outputIndex,
          witnessUtxo: {
              script: Buffer.from(input.output.script, 'hex'),
              value: input.output.satoshis,
          },
          sequence: input.sequenceNumber
      }
      if (input.tapInternalKey) {
          data.tapInternalKey = Buffer.from(input.tapInternalKey, 'hex')
      }
      if (input.tapLeafScript) {
          data.tapLeafScript = input.tapLeafScript
      }
      psbt.addInput(data)
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