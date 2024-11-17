import * as bitcoin from 'bitcoinjs-lib'
import * as secp256k1 from 'tiny-secp256k1'
import ECPairFactory from 'ecpair'
import { bech32m } from 'bech32'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import btc = require('bitcore-lib-inquisition')
import { buildStake, unlockStake2, getTimeLockScript, unlockTimeLock, buildVote } from '../../src/dao/daoContractUtils'
import { AddressType } from '../../src/dao/daoProto'
import { LeafNode, MerkleTreeData } from '../../src/dao/voteMerkleTree'
const request = require('superagent')
import * as dotenv from "dotenv"

dotenv.config()

const TIMEOUT = 10000

const FEE = 1000

const ECPair = ECPairFactory(secp256k1)
const wif = process.env.WIF || ''

const network = bitcoin.networks.bitcoin

const API_URL = 'https://open-api-fractal-testnet.unisat.io'
const KEY = 'Bearer ' + process.env.UNISAT_API_KEY

// Initialize the ECC library
bitcoin.initEccLib(secp256k1);

function getWif() {

  // Generate a random key pair
  const keyPair = ECPair.makeRandom();

  // Get the WIF (Wallet Import Format) from the private key
  const wif = keyPair.toWIF();

  console.log('Generated WIF:', wif);
}

function getAddress(publicKey: Buffer, addressType: AddressType) {

  let payments: any
  if (addressType == AddressType.LEGACY) {
    payments = bitcoin.payments.p2pkh({ pubkey: publicKey, network })
  } else if (addressType == AddressType.NATIVE_WITNESS) {
    payments = bitcoin.payments.p2wpkh({ pubkey: publicKey, network })
  } else if (addressType == AddressType.NESTED_WITNESS) {
    payments = bitcoin.payments.p2sh({
      redeem: bitcoin.payments.p2wpkh({ pubkey: publicKey, network }),
    })
  } else {
    payments = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(publicKey),
      network,
    })
  }
  return {payments, address: payments.address}
}

// generate a taproot address from a WIF
function buildTaprootAddress(wif: string, network, addressType: AddressType) {

  const keyPair = ECPair.fromWIF(wif, network);

  // check if the private key is missing
  if (!keyPair.privateKey) {
    throw new Error('Private key is missing');
  }

  const {payments, address} = getAddress(keyPair.publicKey, addressType)

  console.log('get Address:', address);
  return {payment: payments, keyPair, address}
}

async function getUTXOs(address: string) {
  const res = await request.get(
    `${API_URL}/v1/indexer/address/${address}/utxo-data?cursor=0&size=16`
  ).set('Authorization', KEY).timeout(TIMEOUT)
  if (res.status !== 200 || res.body.code !== 0) {
    console.log("getAddressUtxoRaw failed: res %s", res)
    return false
  }
  return res.body.data.utxo || []
}

function toXOnly(pubkey: Buffer): Buffer {
  return pubkey.subarray(1, 33)
}

function taprootAddressString2Hex(address: string) {
  const decoded = bech32m.decode(address)
  const addressHex = Buffer.from(bech32m.fromWords(decoded.words.slice(1)))
  return addressHex.toString('hex')
}

function taprootAddressHex2String(addressHex: string) {
  const data = Buffer.from(addressHex, 'hex');

  const words = bech32m.toWords(data);

  const taprootWords = [0x01, ...words];

  const taprootAddress = bech32m.encode('bc', taprootWords);
  return taprootAddress
}

function getPsbtFromRawTx(jsonData, network: bitcoin.Network) {

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
      tapInternalKey: Buffer.from(jsonData.tapInternalKey, 'hex'),
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

async function sendTaprootTx2(payment, keyPair, outaddress, outSatoshi, opReturnScript?: Buffer) {
  // get UTXOs
  const utxos = await getUTXOs(payment.address);

  if (utxos.length === 0) {
    console.log('No UTXOs found for this address.');
    return;
  }

  const utxo = utxos[0];

  const tx = new btc.Transaction()
  tx.from({
    txId: utxo.txid,
    outputIndex: utxo.vout,
    satoshis: utxo.satoshi,
    script: new btc.Script(utxo.scriptPk)
  })
  const sumInput = utxo.satoshi

  // opreturn output
  if (opReturnScript) {
    tx.addOutput(new btc.Transaction.Output({
      script: opReturnScript,
      satoshis: 0,
    }))
  }

  // first output
  const inputSatoshi = utxo.satoshi
  const outputAddress = new btc.Address(taprootAddressHex2String(outaddress))
  tx.addOutput(new btc.Transaction.Output({
    script: btc.Script.fromAddress(outputAddress), 
    satoshis: outSatoshi,
  }));

  // charge
  const chargeSats = sumInput - outSatoshi - FEE
  if (chargeSats > 0) {
    tx.addOutput(new btc.Transaction.Output({
      script: btc.Script.fromAddress(new btc.Address(payment.address)),
      satoshis: chargeSats,
    }));
  } else {
    console.log('Insufficient funds', inputSatoshi, outSatoshi, FEE);
    return;
  }

  const jsonData = tx.toJSON()
  jsonData.inputs[0].tapInternalKey = keyPair.publicKey.toString('hex')

  // psbt sign
  const psbt = getPsbtFromRawTx(jsonData, network)

  // sign
  const tweakedSigner = keyPair.tweak(
    bitcoin.crypto.taggedHash('TapTweak', toXOnly(keyPair.publicKey)),
  );

  for (let i = 0; i < psbt.data.inputs.length; i++) {
    psbt.signInput(i, tweakedSigner);
  }

  // validate signature
  psbt.validateSignaturesOfInput(0, (pubkey, msghash, signature) =>
    secp256k1.verifySchnorr(msghash, pubkey, signature)
  );

  psbt.finalizeAllInputs();

  const transaction = psbt.extractTransaction();
  console.log('Transaction Hex:', transaction.toHex());

  return transaction
}

async function sendTaprootTx(payment, keyPair, outaddress, outSatoshi, opReturnScript?: Buffer) {
  // get UTXOs
  const utxos = await getUTXOs(payment.address);

  if (utxos.length === 0) {
    console.log('No UTXOs found for this address.');
    return;
  }

  const utxo = utxos[0];

  const psbt = new bitcoin.Psbt({ network });
  let sumInput = 0
  for (const utxo of utxos) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        script: payment.output,
        value: utxo.satoshi,
      },
      tapInternalKey: payment.internalPubkey,
    });
    sumInput += utxo.satoshi
    if (sumInput >= outSatoshi + FEE) {
      break
    }
  }

  // opreturn output
  if (opReturnScript) {
    psbt.addOutput({
      script: opReturnScript,
      value: 0,
    });
  }

  // first output
  const inputSatoshi = utxo.satoshi
  psbt.addOutput({
    address: taprootAddressHex2String(outaddress), 
    value: outSatoshi,
  });

  // charge
  const chargeSats = sumInput - outSatoshi - FEE
  if (chargeSats > 0) {
    psbt.addOutput({
      address: payment.address,
      value: chargeSats,
    });
  } else {
    console.log('Insufficient funds', inputSatoshi, outSatoshi, FEE);
    return;
  }

  // sign
  const tweakedSigner = keyPair.tweak(
    bitcoin.crypto.taggedHash('TapTweak', toXOnly(keyPair.publicKey)),
  );
  for (let i = 0; i < psbt.data.inputs.length; i++) {
    psbt.signInput(i, tweakedSigner);
  }

  // validate signature
  psbt.validateSignaturesOfInput(0, (pubkey, msghash, signature) =>
    secp256k1.verifySchnorr(msghash, pubkey, signature)
  );

  psbt.finalizeAllInputs();

  const transaction = psbt.extractTransaction();
  console.log('Transaction Hex:', transaction.toHex());

  return transaction
}

/*function getTimeLockScript(xOnlyPubKey: Buffer) {
  const timeLockScript = bitcoin.script.fromASM(`${bitcoin.script.number.encode(LOCK_BLOCK).toString('hex')} OP_CHECKSEQUENCEVERIFY OP_DROP ${xOnlyPubKey.toString('hex')} OP_CHECKSIG`);

  const tapLeaf = Tap.encodeScript(
    timeLockScript
  )
  const [taprootPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: tapLeaf,
    }
  )
  console.log('output Script Address:', taprootAddressHex2String(taprootPubKey))

  const outputScript = bitcoin.script.fromASM(`OP_1 ${taprootPubKey}`)
  return { address: taprootPubKey, outputScript, lockingScript: timeLockScript }
}*/

// build a stake contract
/*function buildStake(publicKey: Buffer, addressType) {
  Stake.loadArtifact()

  let xOnlyPubKey = toXOnly(publicKey)

  const { outputScript } = getTimeLockScript(xOnlyPubKey)

  // realPubKey is a 33 bytes buffer. since the length of taproot pubkey is 32 bytes, we need to add a 0x00 prefix
  let realPubKey = publicKey
  if (addressType == AddressType.TAPROOT) {
    realPubKey = Buffer.concat([
      Buffer.alloc(1, 0),
      xOnlyPubKey,
    ])
  }

  const data = Buffer.concat([
    Buffer.alloc(1, Number(addressType)), // 1 byte
    realPubKey, // 33 bytes
    Buffer.alloc(1, Number(DaoOpType.Unstake)), // 1 byte
    Buffer.from(DAO_SUFFIX), // 7 bytes
  ])
  const opReturnScript = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, data])
  const stake = new Stake(outputScript.toString('hex'), xOnlyPubKey.toString('hex'), opReturnScript.toString('hex'))

  const data2 = Buffer.concat([
    Buffer.alloc(1, Number(addressType)), // 1 byte
    realPubKey, // 33 bytes
    Buffer.alloc(1, Number(DaoOpType.Stake)), // 1 byte
    Buffer.from(DAO_SUFFIX), // 7 bytes
  ])
  const stakeOpreturnScript = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, data2])

  console.log('checkDisableOpCode:', checkDisableOpCode(stake.lockingScript))

  const [tPubKey, cblock] = Tap.getPubKey(
    TAPROOT_ONLY_SCRIPT_PUBKEY.toString('hex'),
    {
      target: Tap.encodeScript(stake.lockingScript.toBuffer())
    }
  )

  console.log('buildStake: Stake taproot address', tPubKey, cblock)
  return { address: tPubKey, stake, opReturnScript: stakeOpreturnScript }
}

export function unlockTimeLock(txid, vout, inputSatoshis, keyPair, addressType: AddressType, fee: number) {

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

async function broadcastTransaction(txHex: string) {
  const data = {
    txHex,
  }
  const res = await request.post(
    `${API_URL}/v1/indexer/local_pushtx`
  ).set('Authorization', KEY).timeout(TIMEOUT).send(data)
  if (res.status !== 200 || res.body.code !== 0) {
    console.log("broadcastTransaction failed: res %s, %s", res.status, res.body)
    return false
  }
  console.log('Transaction broadcasted:', res.body);
  return res.body.data.utxo || []
}

function createVoteMerkleTree(pubKey: Buffer) {
  // tree height, decided by the number of leaves
  const height = 2
  const merkleTree = new MerkleTreeData(Buffer.alloc(0), height)
  const leafNode1 = LeafNode.initFromPubKey(AddressType.TAPROOT, pubKey, BigInt(1000000))
  // fake node
  const leafNode2 = LeafNode.initFromPubKey(AddressType.TAPROOT, Buffer.alloc(33, 2), BigInt(2000000))
  merkleTree.updateLeaf(leafNode1) 
  merkleTree.updateLeaf(leafNode2)
  return merkleTree
}

async function main() {
  const inputAmount = 10000
  const addressType = AddressType.TAPROOT
  const {keyPair, address, payment} = buildTaprootAddress(wif, network, addressType)

  const op = process.argv[2]
  let tx: any
  if (op == 'stake') {
    const { address, opReturnScript } = buildStake(keyPair.publicKey, addressType)
    const inputSatoshis = process.argv[3] ? parseInt(process.argv[3]) : inputAmount
    tx = await sendTaprootTx(payment, keyPair, address, inputSatoshis, opReturnScript)
  } else if (op == 'unstake') {
    const txid = process.argv[3]
    const vout = parseInt(process.argv[4])
    const inputSatoshis = process.argv[5] ? parseInt(process.argv[5]) : inputAmount
    const { address, stake } = buildStake(keyPair.publicKey, addressType)
    const secKey = new btc.PrivateKey.fromWIF(wif, btc.Networks.livenet)
    tx = await unlockStake2(txid, vout, inputSatoshis, stake, secKey, <string>address, 5000, FEE, addressType)
  } else if (op == 'timelock') {
    const inputSatoshis = process.argv[3] ? parseInt(process.argv[3]) : inputAmount
    const { address } = getTimeLockScript(toXOnly(keyPair.publicKey))
    tx = await sendTaprootTx(payment, keyPair, address, inputSatoshis)
  } else if (op == 'timeunlock') {
    const txid = process.argv[3]
    const vout = parseInt(process.argv[4])
    const inputSatoshis = process.argv[5] ? parseInt(process.argv[5]) : inputAmount
    const secKey = new btc.PrivateKey.fromWIF(wif, btc.Networks.livenet)
    tx = unlockTimeLock(txid, vout, inputSatoshis, secKey, addressType, FEE)
  } else if (op == 'createvote') {
    // proposalId can be a tx outpointer or something saving proposal data
    const proposalId = Buffer.alloc(36, 1)
    // create merkle tree of voters
    const merkleTree = createVoteMerkleTree(keyPair.publicKey)
    const vote = buildVote(proposalId, merkleTree.merkleRoot)
    tx = await sendTaprootTx(payment, keyPair, vote.address, 330)
  }

  if (tx) {
    const rawTx = tx.toHex ? tx.toHex() : tx.toString()
    console.log('Transaction hex:', rawTx)
    await broadcastTransaction(rawTx)
  }
}

main()