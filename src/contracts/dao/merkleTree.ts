import {
    assert,
    method,
    ByteString,
    hash160,
    FixedArray,
    SmartContractLib,
} from 'scrypt-ts'

export const HEIGHT = 15

export class MerkleTree extends SmartContractLib {

    @method()
    static updateLeaf(
        oldLeaf: ByteString,
        newLeaf: ByteString,
        neighbor: FixedArray<ByteString, typeof HEIGHT>,
        neighborType: FixedArray<boolean, typeof HEIGHT>,
        oldMerkleRoot: ByteString
    ): ByteString {
        let oldMerkleValue = oldLeaf
        let newMerkleValue = newLeaf
        for (let i = 0; i < HEIGHT; i++) {
            if (neighborType[i]) {
                oldMerkleValue = hash160(oldMerkleValue + neighbor[i])
                newMerkleValue = hash160(newMerkleValue + neighbor[i])
            } else {
                oldMerkleValue = hash160(neighbor[i] + oldMerkleValue)
                newMerkleValue = hash160(neighbor[i] + newMerkleValue)
            }
        }

        assert(oldMerkleValue == oldMerkleRoot, 'oldMerkleValue illegal')
        return newMerkleValue
    }

    @method()
    static verifyLeaf(
        leaf: ByteString,
        neighbor: FixedArray<ByteString, typeof HEIGHT>,
        neighborType: FixedArray<boolean, typeof HEIGHT>,
        merkleRoot: ByteString
    ): boolean {
        let merkleValue = leaf
        for (let i = 0; i < HEIGHT; i++) {
            if (neighborType[i]) {
                merkleValue = hash160(merkleValue + neighbor[i])
            } else {
                merkleValue = hash160(neighbor[i] + merkleValue)
            }
        }

        assert(merkleValue == merkleRoot, 'merkleValue illegal')
        return true
    }
}