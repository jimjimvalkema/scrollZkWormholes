// const { ethers, N } = require("ethers");
// const { poseidon1 } = require("poseidon-lite");
import { poseidon1, poseidon2 } from "poseidon-lite";
import { ethers } from "ethers";
import * as fs from 'node:fs/promises';
import { getHashPathFromProof } from "../../scripts/decodeScrollProof.js"
import { createStoragePositionMapping, getBlockHeaderRlp } from "../../scripts/getScrollProof.js"
import { ZkTrieNode, NodeTypes, leafTypes } from "../../scripts/types/ZkTrieNode.js";
import argParser from 'args-parser'


const PROVER_TOML = 'zkwormholesExample/circuits/smolProver/Prover.toml'
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

const abi = [
    "function balanceOf(address) view returns (uint)"
];
//TODO do actually math or better lib instead of just rerolling :p
export function getSafeRandomNumber() {
    let isBigger = true
    let number = 0n
    while (isBigger) {
        number = ethers.toBigInt(crypto.getRandomValues(new Uint8Array( new Array(32))))
        isBigger = number > FIELD_LIMIT
    }
    return number
}


async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress, [storageKey], blockNumberHex,]
    const proof = await provider.send('eth_getProof', params)
    return proof
}

function paddArray(arr, len = 32, filler = 0, infront = true) {
    if (infront) {
        return [...Array(len - arr.length).fill(filler), ...arr]

    } else {
        return [...arr, ...Array(len - arr.length).fill(filler)]
    }


}

function asPaddedArray(value, len = 32, infront = true) {
    const valueArr = [...ethers.toBeArray(value)]
    return paddArray(valueArr, len, 0, infront)
}

/**
 
 * @typedef hashPaths
 * @property {proofData} account 
 * @property {proofData} storage 

 * @typedef proofData
 * @property {ethers.BytesLike[]} hashPath from leaf-hash-sybling to root-child
 * @property {number[]} nodeTypes from leaf-hash-sybling to root-child
 * @property {ZkTrieNode} leafNode used for the leafHash and nodeKey/hashPathBools in proving
 * 

 * @param {*} BlockHash 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} burnedTokenBalance 
 * @param {*} contractBalance 
 * @param {*} headerRlp 
 * @param {*} nonce_codesize_0 
 * @param {hashPaths} hashPaths 
 * @returns 
 */
export function formatToTomlProver(block,headerRlp, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, maxHashPathLen, maxRlplen, nullifier) {
    //const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return `block_hash = [${[...ethers.toBeArray(block.hash)].map((x)=>`"${x}"`)}] 
nullifier = "${nullifier}"
remint_address = "${remintAddress}"
secret = "${secret}"
user_balance =  [${asPaddedArray(burnedTokenBalance, 32).map((x)=>`"${x}"`)}]

[storage_proof_data]
contract_balance = "${contractBalance}"
header_rlp =  [${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,maxRlplen))].map((x)=>`"${x}"`)}]
header_rlp_len = "${ethers.toBeArray(headerRlp).length}"
nonce_codesize_0 = "${hashPaths.account.leafNode.valuePreimage[0]}"

[storage_proof_data.hash_paths.account_proof]
hash_path = [${paddArray(hashPaths.account.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.account.leafNode.type}"
node_types = [${paddArray(hashPaths.account.nodeTypes, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.account.hashPath.length}"` 
+
`\nhash_path_bools = [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), maxHashPathLen, 0,false).map((x)=>`"${Number(x)}"`)}]`
+
`\n
[storage_proof_data.hash_paths.storage_proof]
hash_path = [${paddArray(hashPaths.storage.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.storage.leafNode.type}"
node_types = [${paddArray(hashPaths.storage.nodeTypes, maxHashPathLen,  0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.storage.hashPath.length}"`
+
`\nhash_path_bools =  [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`"${Number(x)}"`)}]`
}

export async function getProofData(contractAddress = "0x29d801Af49F0D88b6aF01F4A1BD11846f0c96672", burnAddress, blockNumber = 5093419,secret,remintAddress, provider = provider) {
    const tokenContract = new ethers.Contract(contractAddress, abi, provider)

    const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    //slot pos for balances of weth contract
    const mappingSlot = "0x00"
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    const storageKey = createStoragePositionMapping(burnAddress, "address", mappingSlot)
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)


    const hashPaths = {
        "account": getHashPathFromProof(proof.accountProof),
        "storage": getHashPathFromProof(proof.storageProof[0].proof)
    }


    const block = await provider.getBlock(blockNumber)
    const contractBalance = await provider.getBalance(contractAddress)

    const nullifier = hashNullifier(secret, remintAddress)
    return { block, burnedTokenBalance, contractBalance, hashPaths,nullifier, provider }
}

/**
 * 
 * @param {ethers.HexString} input 
 * @param {Number} bytes 
 * @returns 
 */
function Bytes(input, len) {
    const regEx = new RegExp(`.{1,${2 * len}}`, "g")
    return input.slice(2).match(regEx).map((x) => "0x" + x)

}

function hashNullifier(secret, address) {
    return ethers.toBeHex(poseidon2([secret,address]))
}


/**
 * 
 * @param {*} contractAddress 
 * @param {*} blockNumber 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} provider 
 * @returns 
 */
export async function getProofInputs(contractAddress, blockNumber, remintAddress, secret, provider, maxHashPathLen=MAX_HASH_PATH_SIZE, maxRlplen=MAX_RLP_SIZE) {
    const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([secret])).slice(0,20))
    const proofData = await getProofData(contractAddress,burnAddress, Number(blockNumber),secret,remintAddress ,provider)
    const {block,burnedTokenBalance, contractBalance , hashPaths, nullifier}  = {...proofData}
    const headerRlp = await getBlockHeaderRlp(Number(blockNumber), provider)
    return {
        blockData:{block, headerRlp},
        proofData,
        noirJsInputs: {
            storage_proof_data: {
                hash_paths: {
                    account_proof: {
                        hash_path: paddArray(hashPaths.account.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                        leaf_type: (ethers.toBeHex(hashPaths.account.leafNode.type)),
                        node_types: paddArray(hashPaths.account.nodeTypes, maxHashPathLen, 0, false),
                        real_hash_path_len: (ethers.toBeHex(hashPaths.account.hashPath.length)),
                        hash_path_bools: paddArray(hashPaths.account.leafNode.hashPathBools.slice(0, hashPaths.account.hashPath.length).reverse(), maxHashPathLen, false, false),
                    },
                    storage_proof: {
                        hash_path: paddArray(hashPaths.storage.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                        leaf_type: (ethers.toBeHex(hashPaths.storage.leafNode.type)),
                        node_types: paddArray(hashPaths.storage.nodeTypes, maxHashPathLen, 0, false),
                        real_hash_path_len: (ethers.toBeHex(hashPaths.storage.hashPath.length)),
                        hash_path_bools: paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0, hashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false, false),

                    },
                },
                contract_balance: (ethers.toBeHex(contractBalance)),
                header_rlp: [...ethers.toBeArray(ethers.zeroPadBytes(headerRlp, maxRlplen))].map((x) => ethers.toBeHex(x)),
                header_rlp_len: ethers.toBeArray(headerRlp).length,
                nonce_codesize_0: (hashPaths.account.leafNode.valuePreimage[0]),
            },
            secret: (ethers.toBeHex(secret)),
            nullifier: nullifier,
            remint_address: (remintAddress),
            user_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
            block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x))
        }
    }
}


export function formatTest(block,headerRlp, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, maxHashPathLen, maxRlplen) {
    // const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return`
#[test]
fn test_main() {
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [${paddArray(hashPaths.account.hashPath, maxHashPathLen, 0,false)}],
                leaf_type: ${hashPaths.account.leafNode.type},
                node_types: [${paddArray(hashPaths.account.nodeTypes, maxHashPathLen, 0,false)}],
                real_hash_path_len: ${hashPaths.account.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
            storage_proof: Hash_path_proof {
                hash_path: [${paddArray(hashPaths.storage.hashPath, maxHashPathLen, 0,false)}],
                leaf_type: ${hashPaths.storage.leafNode.type},
                node_types: [${paddArray(hashPaths.storage.nodeTypes, maxHashPathLen,  0,false)}],
                real_hash_path_len: ${hashPaths.storage.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
        },
            contract_balance: ${contractBalance},
            header_rlp:[${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,maxRlplen))]}],
            header_rlp_len:${ethers.toBeArray(headerRlp).length},
            nonce_codesize_0:${hashPaths.account.leafNode.valuePreimage[0]},
        };


    let secret = ${secret};

    let remint_address = ${remintAddress};
    let user_balance = [${asPaddedArray(burnedTokenBalance, 32)}];
    let block_hash =  [${[...ethers.toBeArray(block.hash)]}];
    let nullifier = hash_nullifier(secret, remint_address);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);
}`
}

async function setDefaults(args) {
    const defaults = {
        contract: "0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f",
        recipient: "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54",
        secret: 123,
        rpc:  "https://scroll-sepolia.drpc.org",
        blocknumber: "latest", 
        maxTreeDepth: MAX_HASH_PATH_SIZE, 
        maxRlplen: MAX_RLP_SIZE
    }
    for (const defaultParam in defaults) {
        if (args[defaultParam] === undefined) {
            console.log(`"--${defaultParam}=" not set defaulting to: "${defaults[defaultParam]}"`)
            args[defaultParam] = defaults[defaultParam]
        }
    }
    return args
}

async function main() {
    let args = argParser(process.argv)
    if (Object.keys(args).length) {
        args = await setDefaults(args)
        const contractAddress = args["contract"]
        const remintAddress = args["recipient"]
        const secret = args["secret"]
        const providerUrl = args["rpc"]
        const maxHashPathLen = args["maxTreeDepth"]
        const maxRlplen = args["maxRlplen"]
        const provider = new ethers.JsonRpcProvider(providerUrl) 
        const blockNumber =  await provider.getBlockNumber(args["blocknumber"])
        const proofInputs = await getProofInputs(contractAddress,blockNumber,remintAddress,secret,provider,maxHashPathLen, maxRlplen)
        
        // TODO put this in the proper files instead
        console.log("------proofInputs json----------------------------------")
        console.log({proofInputs})
        console.log("--------------------------------------------------------\n")
        console.log("------test main.nr--------------------------------------")
        console.log(formatTest(
            proofInputs.blockData.block, 
            proofInputs.blockData.headerRlp, 
            remintAddress, 
            secret,
            proofInputs.proofData.burnedTokenBalance, 
            proofInputs.proofData.contractBalance , 
            proofInputs.proofData.hashPaths,
            maxHashPathLen,
            maxRlplen
        ))
        console.log("--------------------------------------------------------\n")
        console.log("------Prover.toml---------------------------------------")
        console.log(formatToTomlProver(
            proofInputs.blockData.block, 
            proofInputs.blockData.headerRlp, 
            remintAddress, 
            secret,
            proofInputs.proofData.burnedTokenBalance, 
            proofInputs.proofData.contractBalance , 
            proofInputs.proofData.hashPaths,
            maxHashPathLen,
            maxRlplen,
            proofInputs.noirJsInputs.nullifier
        ).toString())
        console.log("--------------------------------------------------------\n")
    }

}

//main()