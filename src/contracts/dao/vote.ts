import {
    assert,
    PubKey,
    Sig,
    SmartContract,
    prop,
    method,
    ByteString,
    FixedArray,
    hash160,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from '../utils/sigHashUtils'
import { MerkleTree, HEIGHT } from './merkleTree'

export type VoteLeaf = {
    addressType: ByteString // 1 byte
    pubKeyPrefix: ByteString // 1 byte
    xOnlyPubKey: ByteString // 32 byte
    stakeSatoshis: ByteString // 8 byte
}

export class Vote extends SmartContract {
    @prop()
    merkleRoot: ByteString

    @prop()
    proposalId: ByteString

    constructor(merkleRoot: ByteString, proposalId: ByteString) {
        super(...arguments)
        this.merkleRoot = merkleRoot
        this.proposalId = proposalId
    }

    @method()
    public vote(
        choice: bigint,
        shPreimage: SHPreimage,
        // input
        sig: Sig,
        // mekle tree leaf data
        leafData: VoteLeaf,
        neighbour: FixedArray<ByteString, typeof HEIGHT>,
        neighbourType: FixedArray<boolean, typeof HEIGHT>,
    ) {

        // check preimage
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // check sig
        assert(this.checkSig(sig, PubKey(leafData.xOnlyPubKey)), 'invalid signature')

        // verify merkle path
        const leafHash = hash160(leafData.addressType + leafData.pubKeyPrefix + leafData.xOnlyPubKey + leafData.stakeSatoshis)
        assert(MerkleTree.verifyLeaf(leafHash, neighbour, neighbourType, this.merkleRoot))

        // if need add opreturn
    }
}