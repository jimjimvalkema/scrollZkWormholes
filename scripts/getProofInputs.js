// const { ethers, N } = require("ethers");
// const { poseidon1 } = require("poseidon-lite");
import { poseidon1, poseidon2, poseidon3 } from "poseidon-lite";
import { ethers } from "ethers";
import * as fs from 'node:fs/promises';
import { getHashPathFromProof, getBlockHeaderProof, hashStorageKeyMapping, decodeProof } from "../submodules/scrollZkStorageProofs/scripts/decodeScrollProof.js"
import { ZkTrieNode, NodeTypes, leafTypes, BLOCK_HEADER_ORDERING } from "../submodules/scrollZkStorageProofs/scripts/types/ZkTrieNode.js";
import argParser from 'args-parser'

const BALANCES_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"
const NULLIFIERS_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000006"
const PROVER_TOML = 'zkwormholesExample/circuits/smolProver/Prover.toml'
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

// TODO import real abi file instead 
const abi = [
    "function balanceOf(address) view returns (uint256)",
    "function partialNullifiers(bytes32) view returns (uint256)",
    "function reMintAmounts(bytes32) view returns (uint256)",
    "event Remint(bytes32 indexed nullifierKey, uint256 amount)"
];
//import fs from "fs/promises";
// import path from 'path';
// import { fileURLToPath } from 'url';
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);
// const abi = JSON.parse(await fs.readFile(__dirname + "/../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json", "utf-8")).abi
export function getSafeRandomNumber() {
    let isBigger = true
    let number = 0n
    while (isBigger) {
        number = ethers.toBigInt(crypto.getRandomValues(new Uint8Array( new Array(32))))
        isBigger = number > FIELD_LIMIT
    }
    return number
}


async function getProof({contractAddress, storageKey, blockNumber, provider}) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress, [storageKey], blockNumberHex,]
    const proof = await provider.send('eth_getProof', params)
    return proof
}

export function paddArray(arr, len = 32, filler = 0, infront = true) {
    //ethers.assert(arr.length >= len, "tried to pad a array that is larger then specified len")
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
 * @typedef {import("../submodules/scrollZkStorageProofs/scripts/decodeScrollProof.js").decodedProof} decodedProof
 * @param {{
 *      contractAddress: ethers.AddressLike, 
 *      key: ethers.BytesLike, 
 *      keyType: String, 
 *      slot: ethers.BytesLike,
 *      blockNumber: BigInt, 
 *      provider: ethers.Provider
 * }} param0 
 * @returns {Promise<decodedProof>}
 */
export async function getStateProofOfMapping({contractAddress, key, keyType, slot,blockNumber, provider}) {
    const storageKey = hashStorageKeyMapping({key, keyType, slot})
    const proof = await getProof({contractAddress, storageKey, blockNumber, provider})
    const decodedProof = await decodeProof({ proof, provider, blockNumber })
    return decodedProof
    
}

export function hashNullifierValue({amount,nonce,secret}) {
    const nullifierValue = poseidon3([amount,nonce,secret])
    return ethers.zeroPadValue(ethers.toBeHex(nullifierValue),32)
}

export function hashNullifierKey({nonce,secret}) {
    const nullifierKey = poseidon2([nonce,secret])
    return ethers.zeroPadValue(ethers.toBeHex(nullifierKey),32)
}

export function hashBurnAddress({secret}) {
    const hash = ethers.toBeArray(poseidon1([secret])) 
    const burnAddress = hash.slice(0,20)
    return ethers.zeroPadValue(ethers.hexlify(burnAddress),20)
}

// TODO find better name since it get prevSpendAmount and nonce
// TODO rename   noncesPerEventScan=20, chunkSizeEventScan=9000
export async function findLatestNonce({secret, tokenContract, startBlock, noncesPerEventScan=20, chunkSizeEventScan=9999}) {
    const provider = tokenContract.runner.provider
    startBlock = startBlock ? Number(startBlock) : (await provider.getBlockNumber("latest")) - 40000//80000
    //console.log(JSON.stringify(tokenContract))
    let usedNonce = 0n // TODO clean up this while loop so nonce starts at 0n. (for readability)
    let remintEvents = undefined;
    let prevSpendAmount = 0n 
    let txhashes = []
    // do event scanning
    while (remintEvents !== false) {
        const nullifierKeys = Array(noncesPerEventScan).fill(0).map((x,i)=>hashNullifierKey({nonce:usedNonce+BigInt(i), secret}))
        console.log({nullifierKeys})
        remintEvents = await getRemintEventBulk({chunksize:chunkSizeEventScan,nullifierKeys, startBlock, contract:tokenContract})

        if (remintEvents !== false) { //ugly
            usedNonce += BigInt(remintEvents.length)
            const remintedAmount = remintEvents.reduce((accum, event) => accum + BigInt(event.data),0n)
            prevSpendAmount += remintedAmount
            startBlock = remintEvents[remintEvents.length-1].blockNumber
            txhashes = txhashes.concat(remintEvents.map((event)=>event.transactionHash))
        }
    }
    
    let nullifierValue
    while (nullifierValue !== "0x00") {
        const nullifierKey = hashNullifierKey({nonce:usedNonce, secret})
        nullifierValue = ethers.toBeHex(await tokenContract.partialNullifiers(nullifierKey))

        if (nullifierValue !== "0x00") {
            const remintedAmount = await tokenContract.reMintAmounts(nullifierKey)
            prevSpendAmount += remintedAmount
            usedNonce++
        }
    } 
    console.log( {nonce: usedNonce, prevSpendAmount, txhashes})
    return {nonce: usedNonce, prevSpendAmount, txhashes}
}


async function getRemintEvent({nullifierKey, startBlock, contract}) {
    const filter =  contract.filters.Remint([nullifierKey])
    const events = await contract.queryFilter(filter,startBlock)
    if (events[0] !== undefined) {
        return events[0] 
    } else {
        return false
    }
}

//TODO do in bulk ex contract.filters.Remint([nullifierKey1, nullifierKey2, etc])
async function getRemintEventBulk({chunksize=5000,nullifierKeys, startBlock, contract}) {
    const filter =  contract.filters.Remint([...nullifierKeys])
    const events = await queryEventInChunks({chunksize,filter,startBlock,contract})
    console.log({events})
    if (events.length >= 1) {
        return events 
    } else {
        return false
    }
} 
/**
 * 
 * @param {{contract:ethers.Contract}} param0 
 */
async function queryEventInChunks({chunksize=5000,filter,startBlock,contract}){

    const provider = contract.runner.provider
    const lastBlock = await provider.getBlockNumber("latest")
    const numIters = Math.ceil((lastBlock-startBlock)/chunksize)
    const allEvents = []
    console.log({lastBlock,startBlock,chunksize,numIters})
    for (let index = 0; index < numIters; index++) {
        const start = index*chunksize + startBlock
        const stop =  (start + chunksize) > lastBlock ? lastBlock :  (start + chunksize)
        console.log({filter,start,stop})
        const events =  await contract.queryFilter(filter,start,stop)
        allEvents.push(events)
    }
    return allEvents.flat()

}


/**
 * @param {{
 *      contractAddress: ethers.AddressLike, 
 *      burnAddress: ethers.AddressLike,
 *      withdrawAmount: BigInt, 
 *      blockNumber: BigInt | number,
 *      secret: BigInt, 
 *      provider: ethers.Provider
 *  }} params
 * 
 * @typedef hashPath
 * @property {ethers.BytesLike[]} hashPath from leaf-hash-sibling to root-child
 * @property {number[]} nodeTypes from leaf-hash-sibling to root-child
 * @property {ZkTrieNode} leafNode used for the leafHash and nodeKey/hashPathBools in proving
 * @property {ethers.BytesLike} storageRoot used for the leafHash and nodeKey/hashPathBools in proving
 * @typedef {decodedProof} stateProof
 * @typedef {{
 *      amounts: { 
 *          burnedTokenBalance: BigInt,
 *          prevSpendAmount: BigInt,
 *      },
 *      nullifierData : {
 *          nullifierValue: ethers.BytesLike, 
 *          nullifierKey: ethers.BytesLike,
 *          prevNullifierKey: ethers.BytesLike, 
 *          nonce: BigInt,
 *      },
 *      stateProofData : {
 *          rlp: ethers.HexString,
 *          block: ethers.Block,
 *          contractBalance: BigInt, 
 *          balancesStateProof: stateProof,
 *          prevNullifierStateProof: stateProof,
 *          storageRoot: ethers.BytesLike
 *      }
 *   }} RemintProofData 
 * @returns {Promise<RemintProofData>} remintProofData
 */
export async function getRemintProofData({contractAddress, burnAddress,withdrawAmount, blockNumber,deploymentBlock,secret, provider = provider}) {
    // contract data
    const tokenContract = new ethers.Contract(contractAddress, abi, provider)
    const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    const {nonce, prevSpendAmount} = await findLatestNonce({secret, tokenContract})

    // nullifiers
    const nullifierValue = hashNullifierValue({amount: prevSpendAmount + withdrawAmount,nonce,secret})
    const nullifierKey = hashNullifierKey({nonce,secret})
    const prevNullifierKey = hashNullifierKey({nonce: nonce-1n,secret})

    
    // storage proofs
    console.log("getting balance merkle proof")
    const balancesStateProof = await getStateProofOfMapping({contractAddress, key:burnAddress, keyType:"address", slot:BALANCES_SLOT,blockNumber, provider})
    console.log("getting nullifier merkle proof")
    const prevNullifierStateProof = await getStateProofOfMapping({contractAddress, key:prevNullifierKey, keyType:"bytes32", slot:NULLIFIERS_SLOT,blockNumber, provider})
    
    const block = await provider.getBlock(blockNumber)
    const {rlp, byteNibbleOffsets} = await getBlockHeaderProof({blockNumber:Number(blockNumber), provider})
    const contractBalance = await provider.getBalance(contractAddress)


    
    return {   
        // nullifiers
        amounts: {
            withdrawAmount, 
            burnedTokenBalance,
            prevSpendAmount
        },

        nullifierData : {
            nullifierValue: nullifierValue, 
            nullifierKey: nullifierKey,
            prevNullifierKey: prevNullifierKey, 
            nonce,
        },

        stateProofData : {
            storageRoot: balancesStateProof.accountProof.accountPreimage.storageRoot,
            rlp,
            block,
            contractBalance, 
            balancesStateProof,
            prevNullifierStateProof
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
 * @param {{
 *      contractAddress: ethers.AddressLike, 
 *      blockNumber: BigInt,
 *      withdrawAmount: BigInt,
 *      remintAddress: ethers.AddressLike, 
 *      secret: BigInt, 
 *      providerL ethers.Provider, 
 *      maxHashPathLen: number, 
 *      maxRlplen: number
 * }} params
 * 
 * @typedef {{
 *      remint_address: ethers.AddressLike,
 *          withdraw_amount: ethers.BytesLike,
 *          nullifier_value: ethers.BytesLike,
 *          nullifier_key: ethers.BytesLike,
 *          storage_root: ethers.BytesLike,
 *          secret: ethers.BytesLike,
 *          burned_balance: number[],
 *          nonce: ethers.BytesLike,
 *          prev_nullifier_key: ethers.BytesLike,
 *          prev_spend_amount: ethers.BytesLike,
 *          burn_addr_storage_proof: {
 *              hash_path: ethers.BytesLike[],
 *              leaf_type: ethers.BytesLike[],
 *              node_types: ethers.BytesLike[],
 *              real_hash_path_len: Number,
 *              hash_path_bools: Boolean[],
 *          },
 *          prev_nullifier_storage_proof:  {
 *              hash_path: ethers.BytesLike[],
 *              leaf_type: ethers.BytesLike[],
 *              node_types: ethers.BytesLike[],
 *              real_hash_path_len: Number,
 *              hash_path_bools: Boolean[],
 *          }
 *      }} noirJsInputs
 * @typedef {{
 *        blockData:{
 *              block: ethers.Block, 
 *              rlp: ethers.BytesLike
 *        },
 *        proofData: RemintProofData,
 *        noirJsInputs: noirJsInputs
 *    }} ProofInputs
 * @returns {Promise<ProofInputs>} ProofInputs
 */
export async function getProofInputs({contractAddress, blockNumber,withdrawAmount,remintAddress, secret, provider,deploymentBlock, maxHashPathLen=MAX_HASH_PATH_SIZE, maxRlplen=MAX_RLP_SIZE}) {
 
    
    const burnAddress = hashBurnAddress({secret})
    const proofData = await getRemintProofData({contractAddress,burnAddress, withdrawAmount,blockNumber:Number(blockNumber),deploymentBlock,secret, provider})
    const storageRoot = proofData.stateProofData.balancesStateProof.accountProof.accountPreimage.storageRoot
    const {   
        // nullifiers
        amounts: {
            //withdrawAmount, 
            burnedTokenBalance,
            prevSpendAmount,
        },
        
        nullifierData : {
            nullifierValue, 
            nullifierKey,
            prevNullifierKey, 
            nonce,
        },

        stateProofData : {
            rlp,
            block,
            balancesStateProof,
            prevNullifierStateProof
        },
    }  = {...proofData}

    // check if the proof arent too large
    const hashPathLenghts = [
        balancesStateProof.accountProof.hashPath.length,
        balancesStateProof.storageProof.hashPath.length,
        prevNullifierStateProof.accountProof.hashPath.length,
        prevNullifierStateProof.storageProof.hashPath.length
    ]
    const longestHashPath = Math.max(...hashPathLenghts)
    ethers.assert(MAX_HASH_PATH_SIZE >= longestHashPath, "proof size is larger than MAX_HASH_PATH_SIZE")
    // TODO RLP len check

    //ethers.assert(byteNibbleOffsets)
    return {
        blockData:{block, rlp},
        proofData,
        noirJsInputs: {
            // --public inputs--
            remint_address: remintAddress,
            withdraw_amount: ethers.toBeHex(withdrawAmount), //asPaddedArray(withdrawAmount, 32).map((x) => ethers.toBeHex(x)),
            nullifier_value: nullifierValue,
            nullifier_key: nullifierKey,
            //block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x)),
            storage_root: storageRoot,
            //--------------------


            // --private inputs--
            secret: ethers.toBeHex(secret),
            burned_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
            nonce: ethers.toBeHex(nonce),
            prev_nullifier_key: ethers.toBeHex(prevNullifierKey),
            prev_spend_amount: ethers.toBeHex(prevSpendAmount),

            // storage proofs
            burn_addr_storage_proof: {
                hash_path: paddArray(balancesStateProof.storageProof.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                leaf_type: ethers.toBeHex(balancesStateProof.storageProof.leafNode.type),
                node_types: paddArray(balancesStateProof.storageProof.nodeTypes, maxHashPathLen, 0, false),
                real_hash_path_len: (ethers.toBeHex(balancesStateProof.storageProof.hashPath.length)),
                hash_path_bools: paddArray(balancesStateProof.storageProof.leafNode.hashPathBools.slice(0, balancesStateProof.storageProof.hashPath.length).reverse(), maxHashPathLen, false, false),
            },

            prev_nullifier_storage_proof:  {
                hash_path: paddArray(prevNullifierStateProof.storageProof.hashPath, maxHashPathLen, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                leaf_type: ethers.toBeHex(prevNullifierStateProof.storageProof.leafNode.type),
                node_types: paddArray(prevNullifierStateProof.storageProof.nodeTypes, maxHashPathLen, 0, false),
                real_hash_path_len: (ethers.toBeHex(prevNullifierStateProof.storageProof.hashPath.length)),
                hash_path_bools: paddArray(prevNullifierStateProof.storageProof.leafNode.hashPathBools.slice(0, prevNullifierStateProof.storageProof.hashPath.length).reverse(), maxHashPathLen, false, false),
            }
            //--------------------


        }
    }
}
/**
 * @param {Object} obj
 * @param {RemintProofData} obj.proofData 
 * @param {ethers.AddressLike} obj.remintAddress
 * @param {bigint} obj.withdrawAmount
 * @param {ethers.BytesLike} obj.secret
 * @returns 
 */
export function formatTest({proofData, remintAddress, withdrawAmount, secret}) {
    // const headerRlp = await getBlockHeaderRlp(Number(block.number), provider
    console.log(proofData)
    return`
#[test]
fn test_main() {
    //----- public inputs
    let remint_address: Field = ${remintAddress};
    let withdraw_amount:  Field = ${ethers.toBeHex(withdrawAmount)};
    let nullifier_value: Field = ${proofData.nullifierData.nullifierValue};
    let nullifier_key: Field = ${proofData.nullifierData.nullifierKey};
    let block_hash: [u8; 32] = [${paddArray([...ethers.toBeArray(proofData.stateProofData.block.hash)],32,0,true).map((x)=>ethers.toBeHex(x))}];
    
    //-----private inputs -----
    let secret: Field  = ${ethers.toBeHex(secret)};
    let burned_balance: [u8; 32]  = [${paddArray([...ethers.toBeArray(proofData.amounts.burnedTokenBalance)],32,0,true).map((x)=>ethers.toBeHex(x))}];
    let nonce: Field = ${proofData.nullifierData.nonce};
    let prev_nullifier_key: Field = ${proofData.nullifierData.prevNullifierKey};
    let prev_spend_amount: Field = ${proofData.amounts.prevSpendAmount};

    let burn_addr_storage_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [${paddArray(proofData.stateProofData.balancesStateProof.storageProof.hashPath, MAX_HASH_PATH_SIZE,0x0,false)}],
            node_types: [${paddArray(proofData.stateProofData.balancesStateProof.storageProof.nodeTypes, MAX_HASH_PATH_SIZE,0x0,false)}],
            leaf_type:  ${ethers.toBeHex(proofData.stateProofData.balancesStateProof.storageProof.leafNode.type)},
            real_hash_path_len: ${proofData.stateProofData.balancesStateProof.storageProof.hashPath.length},
            hash_path_bools:  [${paddArray(proofData.stateProofData.balancesStateProof.storageProof.leafNode.hashPathBools.slice(0, proofData.stateProofData.balancesStateProof.storageProof.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false)}],
        },
        account_proof: Hash_path_proof {
            hash_path:  [${paddArray(proofData.stateProofData.balancesStateProof.accountProof.hashPath, MAX_HASH_PATH_SIZE,0x0,false)}],
            node_types: [${paddArray(proofData.stateProofData.balancesStateProof.accountProof.nodeTypes, MAX_HASH_PATH_SIZE,0x0,false)}],
            leaf_type:  ${ethers.toBeHex(proofData.stateProofData.balancesStateProof.accountProof.leafNode.type)},
            real_hash_path_len: ${proofData.stateProofData.balancesStateProof.accountProof.hashPath.length},
            hash_path_bools: [${paddArray(proofData.stateProofData.balancesStateProof.accountProof.leafNode.hashPathBools.slice(0, proofData.stateProofData.balancesStateProof.accountProof.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false)}],
        }
    };
    let prev_nullifier_storage_proof = Hash_paths_state_proof {
        storage_proof: Hash_path_proof {
            hash_path:  [${paddArray(proofData.stateProofData.prevNullifierStateProof.storageProof.hashPath, MAX_HASH_PATH_SIZE,0x0,false)}],
            node_types: [${paddArray(proofData.stateProofData.prevNullifierStateProof.storageProof.nodeTypes, MAX_HASH_PATH_SIZE,0x0,false)}],
            leaf_type:  ${ethers.toBeHex(proofData.stateProofData.prevNullifierStateProof.storageProof.leafNode.type)},
            real_hash_path_len: ${proofData.stateProofData.prevNullifierStateProof.storageProof.hashPath.length},
            hash_path_bools:  [${paddArray(proofData.stateProofData.prevNullifierStateProof.storageProof.leafNode.hashPathBools.slice(0, proofData.stateProofData.prevNullifierStateProof.storageProof.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false)}],
        },
        account_proof: Hash_path_proof {
            hash_path:  [${paddArray(proofData.stateProofData.prevNullifierStateProof.accountProof.hashPath, MAX_HASH_PATH_SIZE,0x0,false)}],
            node_types: [${paddArray(proofData.stateProofData.prevNullifierStateProof.accountProof.nodeTypes, MAX_HASH_PATH_SIZE,0x0,false)}],
            leaf_type:  ${ethers.toBeHex(proofData.stateProofData.prevNullifierStateProof.accountProof.leafNode.type)},
            real_hash_path_len: ${proofData.stateProofData.prevNullifierStateProof.accountProof.hashPath.length},
            hash_path_bools:  [${paddArray(proofData.stateProofData.prevNullifierStateProof.accountProof.leafNode.hashPathBools.slice(0, proofData.stateProofData.prevNullifierStateProof.accountProof.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false)}],
        }
    };
    let contract_data = Contract_proof_data {
        balance: ${proofData.stateProofData.contractBalance},
        nonce_codesize_0: ${ethers.zeroPadValue(ethers.toBeHex(proofData.stateProofData.balancesStateProof.accountProof.leafNode.valuePreimage[0]),32)},
        header_rlp: [${[...ethers.toBeArray(ethers.zeroPadBytes(proofData.stateProofData.rlp, MAX_RLP_SIZE))].map((x) => ethers.toBeHex(x))}],
        header_rlp_len: ${[...ethers.toBeArray(proofData.stateProofData.rlp,)].length},
    };

    main(
        //----- public inputs
        remint_address,
        withdraw_amount,
        nullifier_value,
        nullifier_key,
        block_hash,
        //-----private inputs -----
        secret,
        burned_balance,
        nonce,
        prev_nullifier_key,
        prev_spend_amount,
        burn_addr_storage_proof,
        prev_nullifier_storage_proof,
        contract_data,
    );`
}