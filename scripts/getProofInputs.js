// const { ethers, N } = require("ethers");
// const { poseidon1 } = require("poseidon-lite");
import { poseidon1, poseidon2, poseidon3 } from "poseidon-lite";
import { ethers } from "ethers";
import * as fs from 'node:fs/promises';
import { getHashPathFromProof, getBlockHeaderProof, hashStorageKeyMapping } from "../submodules/scrollZkStorageProofs/scripts/decodeScrollProof.js"
import { ZkTrieNode, NodeTypes, leafTypes, BLOCK_HEADER_ORDERING } from "../submodules/scrollZkStorageProofs/scripts/types/ZkTrieNode.js";
import argParser from 'args-parser'

const BALANCES_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"
const NULLIFIERS_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000006"
const PROVER_TOML = 'zkwormholesExample/circuits/smolProver/Prover.toml'
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const MAX_HASH_PATH_SIZE = 26;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

// TODO import real abi file instead
const abi = [
    "function balanceOf(address) view returns (uint256)",
    "function partialNullifiers(bytes32) view returns (uint256)",
    "function remintedAmounts(bytes32) view returns (uint256)"
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

export function paddArray(arr, len = 32, filler = 0, infront = true) {
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

export async function getStorageProofOfMapping({contractAddress, key, keyType, slot,blockNumber, provider}) {
    const storageKey = hashStorageKeyMapping(key, keyType, slot)
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)
    console.log({proof})

    const hashPaths = {
        "account": getHashPathFromProof(proof.accountProof),
        "storage": getHashPathFromProof(proof.storageProof[0].proof)
    }
    console.log(hashPaths)
    return hashPaths
    
}

export function hashNullifier(amount,nonce,secret) {
    // const hashedSecret = poseidon1([secret]) 
    // const nullifier = poseidon2([secret,hashedSecret])
    const nullifier = poseidon3([amount,nonce,secret])
    console.log({nullifier})
    console.log({nullifierHex: ethers.toBeHex(nullifier)})
    console.log({nullifierHexPad: ethers.zeroPadValue(ethers.toBeHex(nullifier),32)})
    return ethers.zeroPadValue(ethers.toBeHex(nullifier),32)
}

export function hashNullifierId(nonce,secret) {
    // const hashedSecret = poseidon1([secret]) 
    // const nullifier = poseidon2([secret,hashedSecret])
    // return ethers.zeroPadValue(ethers.toBeHex(nullifier),32)
    const nullifierId = poseidon2([nonce,secret])
    // console.log({nullifierId})
    // console.log({nullifierIdHex: ethers.zeroPadValue(ethers.toBeHex(nullifierId),32)})
    return ethers.zeroPadValue(ethers.toBeHex(nullifierId),32)
}

export function hashBurnAddress(secret) {
    const hash = ethers.toBeArray(poseidon1([secret])) 
    const burnAddress = hash.slice(0,20)
    return ethers.zeroPadValue(ethers.hexlify(burnAddress),20)
}

// TODO find better name since it get prevSpendAmount and nonce
export async function findLatestNonce(secret, tokenContract) {
    //console.log(JSON.stringify(tokenContract))
    let nonce = -1n // TODO clean up this while loop so nonce starts at 0n. (for readability)
    let nullifier = undefined;
    let prevSpendAmount = 0n 
    while (nullifier !== "0x00") {
        nonce++;
        const nullifierId = hashNullifierId(nonce, secret)
        const remintedAmount = await tokenContract.remintedAmounts(nullifierId)
        prevSpendAmount += remintedAmount
        nullifier = ethers.toBeHex(await tokenContract.partialNullifiers(nullifierId))
        console.log({nullifier, nonce, prevSpendAmount})
    }
    return {nonce, prevSpendAmount}
}

export async function getProofData(contractAddress, burnAddress,withdrawAmount, blockNumber = 5093419,secret, provider = provider) {
    // contract data
    const tokenContract = new ethers.Contract(contractAddress, abi, provider)
    const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    const {nonce, prevSpendAmount} = await findLatestNonce(secret, tokenContract)

    // nullifiers
    const nullifier = hashNullifier(prevSpendAmount + withdrawAmount,nonce,secret)
    const nullifierId = hashNullifierId(nonce,secret)
    const prevNullifierId = hashNullifierId(nonce-1n,secret)

    
    // storage proofs
    console.log("getting balance merkle proof")
    const balancesHashPaths = await getStorageProofOfMapping({contractAddress, key:burnAddress, keyType:"address", slot:BALANCES_SLOT,blockNumber, provider})
    console.log("getting nullifier merkle proof")
    const prevNullifierHashPaths = await getStorageProofOfMapping({contractAddress, key:prevNullifierId, keyType:"bytes32", slot:NULLIFIERS_SLOT,blockNumber, provider})
    console.log({prevNullifierLeaf: prevNullifierHashPaths.storage.leafNode})
    console.log({BalancesLeaf: balancesHashPaths.storage.leafNode})
    
    const block = await provider.getBlock(blockNumber)
    const contractBalance = await provider.getBalance(contractAddress)


    
    return {   
        // nullifiers
        amounts: {
            withdrawAmount, 
            burnedTokenBalance,
            prevSpendAmount
        },

        nullifierData : {
            nullifier, 
            nullifierId,
            prevNullifierId, 
            nonce,
        },

        storageProofData : {
            block,
            contractBalance, 
            balancesHashPaths,
            prevNullifierHashPaths
        },
    }
    //return { block, burnedTokenBalance, contractBalance, balancesHashPaths, prevNullifierHashPaths, nullifier, provider }
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

/**
 * 
 * @param {*} contractAddress 
 * @param {*} blockNumber 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} provider 
 * @returns 
 */

export async function getProofInputs(contractAddress, blockNumber,withdrawAmount,remintAddress, secret, provider, maxHashPathLen=MAX_HASH_PATH_SIZE, maxRlplen=MAX_RLP_SIZE) {
    const burnAddress = hashBurnAddress(secret)
    const proofData = await getProofData(contractAddress,burnAddress, withdrawAmount,Number(blockNumber),secret, provider)
    const {   
        // nullifiers
        amounts: {
            //withdrawAmount, 
            burnedTokenBalance,
            prevSpendAmount,
        },
        
        nullifierData : {
            nullifier, 
            nullifierId,
            prevNullifierId, 
            nonce,
        },

        storageProofData : {
            block,
            contractBalance, 
            balancesHashPaths,
            prevNullifierHashPaths
        },
    }  = {...proofData}

    
    const {rlp:headerRlp, byteNibbleOffsets} = await getBlockHeaderProof(Number(blockNumber), provider)
    //ethers.assert(byteNibbleOffsets)
    return {
        blockData:{block, headerRlp},
        proofData,
        noirJsInputs: {
            // --public inputs--
            remint_address: remintAddress,
            withdraw_amount: ethers.toBeHex(withdrawAmount), //asPaddedArray(withdrawAmount, 32).map((x) => ethers.toBeHex(x)),
            nullifier: nullifier,
            nullifier_id: nullifierId,
            block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x)),
            //--------------------


            // --private inputs--
            secret: ethers.toBeHex(secret),
            burned_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
            nonce: ethers.toBeHex(nonce),
            prev_nullifier_id: ethers.toBeHex(prevNullifierId),
            prev_spend_amount: ethers.toBeHex(prevSpendAmount),

            // storage proofs
            burn_addr_storage_proof: {
                account_proof: {
                    hash_path: paddArray(balancesHashPaths.account.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                    leaf_type: ethers.toBeHex(balancesHashPaths.account.leafNode.type),
                    node_types: paddArray(balancesHashPaths.account.nodeTypes, maxHashPathLen, 0, false),
                    real_hash_path_len: ethers.toBeHex(balancesHashPaths.account.hashPath.length),
                    hash_path_bools: paddArray(balancesHashPaths.account.leafNode.hashPathBools.slice(0, balancesHashPaths.account.hashPath.length).reverse(), maxHashPathLen, false, false),
                },
                storage_proof: {
                    hash_path: paddArray(balancesHashPaths.storage.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                    leaf_type: ethers.toBeHex(balancesHashPaths.storage.leafNode.type),
                    node_types: paddArray(balancesHashPaths.storage.nodeTypes, maxHashPathLen, 0, false),
                    real_hash_path_len: (ethers.toBeHex(balancesHashPaths.storage.hashPath.length)),
                    hash_path_bools: paddArray(balancesHashPaths.storage.leafNode.hashPathBools.slice(0, balancesHashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false, false),
                },
            },

            prev_nullifier_storage_proof: {
                account_proof: {
                    hash_path: paddArray(prevNullifierHashPaths.account.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                    leaf_type: ethers.toBeHex(prevNullifierHashPaths.account.leafNode.type),
                    node_types: paddArray(prevNullifierHashPaths.account.nodeTypes, maxHashPathLen, 0, false),
                    real_hash_path_len: ethers.toBeHex(prevNullifierHashPaths.account.hashPath.length),
                    hash_path_bools: paddArray(prevNullifierHashPaths.account.leafNode.hashPathBools.slice(0, prevNullifierHashPaths.account.hashPath.length).reverse(), maxHashPathLen, false, false),
                },
                storage_proof: {
                    hash_path: paddArray(prevNullifierHashPaths.storage.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                    leaf_type: ethers.toBeHex(prevNullifierHashPaths.storage.leafNode.type),
                    node_types: paddArray(prevNullifierHashPaths.storage.nodeTypes, maxHashPathLen, 0, false),
                    real_hash_path_len: (ethers.toBeHex(prevNullifierHashPaths.storage.hashPath.length)),
                    hash_path_bools: paddArray(prevNullifierHashPaths.storage.leafNode.hashPathBools.slice(0, prevNullifierHashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false, false),

                },
            },

            contract_data: {
                balance: (ethers.toBeHex(contractBalance)),
                nonce_codesize_0: (balancesHashPaths.account.leafNode.valuePreimage[0]),
                header_rlp: [...ethers.toBeArray(ethers.zeroPadBytes(headerRlp, maxRlplen))].map((x) => ethers.toBeHex(x)),
                header_rlp_len: ethers.toBeArray(headerRlp).length,
            }
            //--------------------


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
    let nullifier = hash_nullifier(secret);
    main(remint_address,user_balance,block_hash,nullifier,secret,storage_proof_data);
}`
}

async function setDefaults(args) {
    const defaults = {
        contract: "0xe175E40d10963BD703722034E53F838D74014BE1",
        recipient: "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54",
        secret: 123,
        rpc:  "https://sepolia-rpc.scroll.io/",
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