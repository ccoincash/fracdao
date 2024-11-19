import { AddressType } from "./daoProto"
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import btc = require('bitcore-lib-inquisition')

const LEFT_FLAG = Buffer.from('01', 'hex')
const RIGHT_FLAG = Buffer.from('00', 'hex')

const LEAF_NODE_SIZE = 42

export const getUInt16Buf = function (amount: number) {
    const buf = Buffer.alloc(2, 0)
    buf.writeUInt16LE(amount)
    return buf
}

export const getUInt32Buf = function (amount: number) {
    const buf = Buffer.alloc(4, 0)
    buf.writeUInt32LE(amount)
    return buf
}

export const getUInt64Buf = function (amount: bigint | number) {
    const buf = Buffer.alloc(8, 0)
    buf.writeBigUInt64LE(BigInt(amount))
    return buf
}

export class LeafNode {
    addressType: AddressType
    pubKey: Buffer
    stakeAmount: bigint

    constructor(data: Buffer) {
        this.addressType = AddressType.TAPROOT
        this.pubKey = Buffer.alloc(33, 0)
        this.stakeAmount = BigInt(0)
        this.unserialize(data)
    }

    static EmptyLeafNode() {
        const leaf = new LeafNode(Buffer.alloc(LEAF_NODE_SIZE, 0))
        return leaf
    }

    static initFromPubKey(addressType: AddressType, pubKey: Buffer, stakeAmount: bigint) {
        const leaf = new LeafNode(Buffer.alloc(LEAF_NODE_SIZE, 0))
        leaf.addressType = addressType
        leaf.pubKey = pubKey
        leaf.stakeAmount = stakeAmount
        return leaf
    }

    static initFromLeaf(leaf: LeafNode) {
        const newLeaf = new LeafNode(leaf.serialize())
        return newLeaf
    }

    get hash() {
        return btc.crypto.Hash.sha256ripemd160(this.serialize())
    }

    key() {
        return Buffer.concat([Buffer.alloc(1, this.addressType), this.pubKey]).toString('hex')
    }

    size() {
        return LEAF_NODE_SIZE
    }

    serialize() {
        let buf = Buffer.concat([
            Buffer.from([this.addressType]),
            this.pubKey,
            getUInt64Buf(this.stakeAmount),
        ])
        return buf
    }

    unserialize(data: Buffer) {
        this.addressType = data.readUInt8(0)
        this.pubKey = data.subarray(1, 33)
        this.stakeAmount = data.readBigUInt64LE(33)
    }

    isEmpty() {
        if (this.stakeAmount === BigInt(0)) {
            return true
        }
        return false
    }

    toString() {
        const data = {
            addressType: this.addressType,
            pubKey: this.pubKey.toString('hex'),
            stakeAmount: this.stakeAmount.toString(),
        }
        return JSON.stringify(data)
    }
}

export class MerkleTreeData {
    leafArray: LeafNode[] = []
    height: number
    leafMap: Map<string, number>
    emptyHashs: Buffer[] = []
    hashNodes: Buffer[][] = []
    maxLeafSize: number

    constructor(leafData: Buffer, height: number) {

        this.height = height
        this.maxLeafSize = Math.pow(2, this.height - 1)
        this.leafMap = new Map()

        let pos = 0
        while (pos < leafData.length) {
            const leafNodeLen = leafData.readUInt32LE(pos)
            const leafNodeData = leafData.subarray(pos + 4, pos + 4 + leafNodeLen)
            pos += 4 + leafNodeLen
            const leafNode = new LeafNode(leafNodeData)
            this.leafArray.push(leafNode)
            this.leafMap.set(leafNode.key(), this.leafArray.length - 1)
        }

        const emptyNodeBuf = LeafNode.EmptyLeafNode().serialize()
        let emptyHash = btc.crypto.Hash.sha256ripemd160(emptyNodeBuf)
        this.emptyHashs.push(emptyHash)
        for (let i = 1; i < height; i++) {
            const prevHash = this.emptyHashs[i - 1]
            this.emptyHashs[i] = this.getHash(prevHash, prevHash)
        }

        this.buildMerkleTree()
    }

    getHash(buf1: Buffer, buf2: Buffer) {
        return btc.crypto.Hash.sha256ripemd160(Buffer.concat([buf1, buf2]))
    }

    get merkleRoot() {
        return this.hashNodes[this.hashNodes.length - 1][0]
    }

    get size() {
        return this.leafArray.length
    }

    get addressCount() {
        return this.leafArray.length
    }

    buildMerkleTree() {
        this.hashNodes = []
        let prevHash: Buffer[] = []
        let curHash: Buffer[] = []

        for (let i = 0; i < this.leafArray.length; i++) {
            prevHash.push(this.leafArray[i].hash)
        }
        if (prevHash.length > 0) {
            this.hashNodes.push(prevHash)
        } else {
            this.hashNodes.push([this.emptyHashs[0]])
        }

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            curHash = []
            for (let j = 0; j < prevHash.length; ) {
                if (j + 1 < prevHash.length) {
                    curHash.push(this.getHash(prevHash[j], prevHash[j + 1]))
                } else {
                    curHash.push(this.getHash(prevHash[j], this.emptyHashs[i - 1]))
                }
                j += 2
            }
            this.hashNodes.push(curHash)
        }
    }

    updateLeafBuf(leafBuf: Buffer, leafIndex: number|undefined) {
        let leafNode = new LeafNode(leafBuf)
        this.updateLeaf(leafNode, leafIndex)
    }

    updateLeaf(leafNode: LeafNode, leafIndex: number|undefined = -1) {
        if (leafIndex < 0) {
            leafIndex = this.leafMap.get(leafNode.key())
        }
        let oldLeafBuf: Buffer

        // leafNode already in the tree 
        if (leafIndex !== undefined) {
            const oldLeaf = this.leafArray[leafIndex]
            this.leafMap.delete(oldLeaf.key())
            oldLeafBuf = oldLeaf.serialize()
            this.leafArray[leafIndex] = leafNode
        } else {
            let emptyIndex = -1
            for (let i = 0; i < this.leafArray.length; i++) {
                if (this.leafArray[i].isEmpty()) {
                    emptyIndex = i
                    break
                }
            }
            // find empty node
            if (emptyIndex >= 0) {

                const emptyNode = this.leafArray[emptyIndex]
                if (!emptyNode.isEmpty()) {
                    throw Error('empty node illeage' + String(emptyNode.toString()))
                }
                oldLeafBuf = emptyNode.serialize()
                this.leafArray[emptyIndex] = leafNode
                this.leafMap.delete(emptyNode.key())

                leafIndex = emptyIndex
            } else {
                // check size
                if (this.leafArray.length >= this.maxLeafSize) {
                    throw new Error("merkle tree is full")
                }
                oldLeafBuf = LeafNode.EmptyLeafNode().serialize()
                this.leafArray.push(leafNode)
                leafIndex = this.leafArray.length - 1
            }
        }
        this.leafMap.set(leafNode.key(), leafIndex)

        // return merkle path
        const merklePath = this.updateMerkleTree(leafNode, leafIndex)
        return {oldLeafBuf, merklePath, leafIndex}
    }

    calMerkleRoot(leafNode: Buffer, merklePath: Buffer) {
        const height = Math.floor(merklePath.length / 33)

        let merkleValue = btc.crypto.Hash.sha256ripemd160(leafNode)
        console.log('merkleValue: ', merkleValue.toString('hex'), leafNode.toString('hex'))
        for (let i = 0; i < height; i++) {
            const neighbor = merklePath.subarray(i * 33, i * 33 + 32)
            const left = merklePath.readUInt8(i * 33 + 32)

            if (left === 1) {
                merkleValue = this.getHash(merkleValue, neighbor)
            } else {
                merkleValue = this.getHash(neighbor, merkleValue)
            }
            console.log('merkleValue: ', merkleValue.toString('hex'))
        }
        return merkleValue
    }

    updateMerkleTree(leafNode: LeafNode, leafIndex: number) {
        let prevHash = this.hashNodes[0]
        let paths: Buffer[] = []

        if (leafIndex < prevHash.length) {
            prevHash[leafIndex] = leafNode.hash
        } else {
            prevHash.push(leafNode.hash)
        }

        let prevIndex = leafIndex

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            const curHash = this.hashNodes[i]

            const curIndex = Math.floor(prevIndex / 2)
            // right node
            if (prevIndex % 2 === 1) {
                const newHash = this.getHash(prevHash[prevIndex - 1], prevHash[prevIndex])
                curHash[curIndex] = newHash
                paths.push(Buffer.concat([prevHash[prevIndex - 1], RIGHT_FLAG]))
            } else { // left node
                // new add
                let newHash
                if (curIndex >= curHash.length) {
                    newHash = this.getHash(prevHash[prevIndex], this.emptyHashs[i - 1])
                    if (curHash.length !== curIndex) {
                        throw Error('wrong curHash')
                    }
                    curHash.push(newHash)
                    paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                } else {
                    if (prevHash.length > prevIndex + 1) {
                        newHash = this.getHash(prevHash[prevIndex], prevHash[prevIndex + 1])
                        paths.push(Buffer.concat([prevHash[prevIndex + 1], LEFT_FLAG]))
                    } else {
                        newHash = this.getHash(prevHash[prevIndex], this.emptyHashs[i - 1])
                        paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                    }
                    curHash[curIndex] = newHash
                }
            }
            prevIndex = curIndex
        }

        // push
        //paths.push(Buffer.concat([this.hashNodes[this.hashNodes.length - 1][0], ROOT_FLAG]))
        return Buffer.concat(paths)
    }

    has(key: Buffer) {
        return this.leafMap.has(key.toString('hex'))
    }

    get(key: Buffer) {
        const index = this.leafMap.get(key.toString('hex'))
        if (index !== undefined) {
            return new LeafNode(this.leafArray[index].serialize())
        }
        return undefined
    }

    getMerklePath(key: Buffer) {

        const leafIndex = this.leafMap.get(key.toString('hex'))
        if (leafIndex == undefined) {
            return undefined
        }

        const leafNode = this.leafArray[leafIndex]

        let prevHash = this.hashNodes[0]
        //let paths: Buffer[] = []
        let neighbor: string[] = []
        let neighborType: boolean[] = []

        if (leafIndex < prevHash.length) {
            prevHash[leafIndex] = leafNode.hash
        } else {
            prevHash.push(leafNode.hash)
        }

        let prevIndex = leafIndex

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            const curHash = this.hashNodes[i]

            const curIndex = Math.floor(prevIndex / 2)
            // right node
            if (prevIndex % 2 === 1) {
                //paths.push(Buffer.concat([prevHash[prevIndex - 1], RIGHT_FLAG]))
                neighbor.push(prevHash[prevIndex - 1].toString('hex'))
                neighborType.push(false)
            } else { // left node
                if (curIndex >= curHash.length) {
                    //paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                    neighbor.push(this.emptyHashs[i - 1].toString('hex'))
                } else {
                    if (prevHash.length > prevIndex + 1) {
                        //paths.push(Buffer.concat([prevHash[prevIndex + 1], LEFT_FLAG]))
                        neighbor.push(prevHash[prevIndex + 1].toString('hex'))
                    } else {
                        //paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                        neighbor.push(this.emptyHashs[i - 1].toString('hex'))
                    }
                }
                neighborType.push(true)
            }
            prevIndex = curIndex
        }

        // push
        //paths.push(Buffer.concat([this.hashNodes[this.hashNodes.length - 1][0], ROOT_FLAG]))
        return {neighbor, neighborType, leafNode}
    }

    serializeLeaf() {
        let data = Buffer.alloc(0)
        for (const leaf of this.leafArray) {
            const leafData = leaf.serialize()
            data = Buffer.concat([
                data,
                getUInt32Buf(leafData.length),
                leafData
            ])
        }
        return data
    }
}