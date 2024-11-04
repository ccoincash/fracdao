import {
    assert,
    PubKey,
    Sig,
    SmartContract,
    prop,
    sha256,
    method,
    ByteString,
    toByteString,
    len,
    int2ByteString,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from '../utils/sigHashUtils'

export class Stake extends SmartContract {
    // a taproot output with a time lock script
    @prop()
    outputScript: ByteString

    @prop()
    xOnlyPubKey: ByteString

    // op_return with unstake data
    @prop()
    opReturnScript: ByteString

    constructor(outputScript: ByteString, xOnlyPubKey: ByteString, opReturnScript: ByteString) {
        super(...arguments)
        this.outputScript = outputScript
        this.xOnlyPubKey = xOnlyPubKey
        this.opReturnScript = opReturnScript
    }

    /**
     * Unstake user's assets
     * @param shPreimage - The preimage of tx 
     * @param sig - The schnorr signature
     * @param stakeOutputAddress - The taproot address of stake contract
     * @param remainningAmountBytes - The remaining satoshi bytes in stake contract
     * @param withdrawAmountByte - The withdraw satoshi bytes to user
     */
    @method()
    public unstake(
        shPreimage: SHPreimage,
        sig: Sig,
        stakeOutputAddress: ByteString,
        remainningAmountBytes: ByteString,
        withdrawAmountByte: ByteString
    ) {
        // check preimage
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // check sig
        assert(this.checkSig(sig, PubKey(this.xOnlyPubKey)), 'invalid signature')

        // verify stakeOutputAddress
        assert(sha256(int2ByteString(len(stakeOutputAddress)) + stakeOutputAddress) == shPreimage.hashSpentScripts)

        // build output
        const withdrawOutput =
            withdrawAmountByte +
            int2ByteString(len(this.outputScript)) +
            this.outputScript

        const opReturnOutput = toByteString('0000000000000000') + int2ByteString(len(this.opReturnScript)) + this.opReturnScript

        let stakeOutput = toByteString('')
        if (remainningAmountBytes !== toByteString('0000000000000000')) {
            stakeOutput =
                remainningAmountBytes + toByteString('22') + stakeOutputAddress
        }

        const hashOutputs = sha256(
            opReturnOutput + withdrawOutput + stakeOutput
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }
}
