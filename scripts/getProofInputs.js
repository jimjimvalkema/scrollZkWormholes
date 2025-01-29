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
 * @param {*} BlockHash 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} burnedTokenBalance 
 * @param {*} contractBalance 
 * @param {*} headerRlp 
 * @param {*} nonce_codesize_0 
 * @param {stateProof} hashPaths 
 * @returns 
 */
export async function formatToTomlProver(proofData) {
    //const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
return `    
block_hash = [${[...ethers.toBeArray(proofData. block.hash)].map((x)=>`"${x}"`)}]
burned_balance =  [${asPaddedArray(burnedTokenBalance, 32).map((x)=>`"${x}"`)}]
nonce = "${nonce}"
nullifier = "${nullifier}"
nullifier_id = "${nunullifierId}"
prev_nullifier_id = "${prevNullifierId}"
prev_spend_amount = "${prevSpendSmount}"
remint_address = "${remintAddress}"
secret = "${secret}"
withdraw_amount = "${withdrawAmount}"

[burn_addr_storage_proof.account_proof]
hash_path = [${paddArray(hashPaths.accountProof.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
hash_path_bools = 
leaf_type = ""
node_types = 
real_hash_path_len = ""

[burn_addr_storage_proof.storage_proof]
hash_path = 
hash_path_bools = 
leaf_type = ""
node_types = 
real_hash_path_len = ""

[contract_data]
balance = ""
header_rlp = 
header_rlp_len = ""
nonce_codesize_0 = ""

[prev_nullifier_storage_proof.account_proof]
hash_path = 
hash_path_bools = 
leaf_type = ""
node_types = 
real_hash_path_len = ""

[prev_nullifier_storage_proof.storage_proof]
hash_path = 
hash_path_bools = 
leaf_type = ""
node_types = 
real_hash_path_len = ""
`
}
//     return `block_hash = [${[...ethers.toBeArray(block.hash)].map((x)=>`"${x}"`)}] 
// nullifier = "${nullifier}"
// remint_address = "${remintAddress}"
// secret = "${secret}"
// user_balance =  [${asPaddedArray(burnedTokenBalance, 32).map((x)=>`"${x}"`)}]

// [storage_proof_data]
// contract_balance = "${contractBalance}"
// header_rlp =  [${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,maxRlplen))].map((x)=>`"${x}"`)}]
// header_rlp_len = "${ethers.toBeArray(headerRlp).length}"
// nonce_codesize_0 = "${hashPaths.accountProof.leafNode.valuePreimage[0]}"

// [storage_proof_data.hash_paths.account_proof]
// hash_path = [${paddArray(hashPaths.accountProof.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
// leaf_type = "${hashPaths.accountProof.leafNode.type}"
// node_types = [${paddArray(hashPaths.accountProof.nodeTypes, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
// real_hash_path_len = "${hashPaths.accountProof.hashPath.length}"` 
// +
// `\nhash_path_bools = [${paddArray(hashPaths.accountProof.leafNode.hashPathBools.slice(0,hashPaths.accountProof.hashPath.length).reverse(), maxHashPathLen, 0,false).map((x)=>`"${Number(x)}"`)}]`
// +
// `\n
// [storage_proof_data.hash_paths.storage_proof]
// hash_path = [${paddArray(hashPaths.storageProof.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
// leaf_type = "${hashPaths.storageProof.leafNode.type}"
// node_types = [${paddArray(hashPaths.storageProof.nodeTypes, maxHashPathLen,  0,false).map((x)=>`"${x}"`)}]
// real_hash_path_len = "${hashPaths.storageProof.hashPath.length}"`
// +
// `\nhash_path_bools =  [${paddArray(hashPaths.storageProof.leafNode.hashPathBools.slice(0,hashPaths.storageProof.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`"${Number(x)}"`)}]`
// }
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

export function hashNullifier({amount,nonce,secret}) {
    const nullifier = poseidon3([amount,nonce,secret])
    return ethers.zeroPadValue(ethers.toBeHex(nullifier),32)
}

export function hashNullifierId({nonce,secret}) {
    const nullifierId = poseidon2([nonce,secret])
    return ethers.zeroPadValue(ethers.toBeHex(nullifierId),32)
}

export function hashBurnAddress({secret}) {
    const hash = ethers.toBeArray(poseidon1([secret])) 
    const burnAddress = hash.slice(0,20)
    return ethers.zeroPadValue(ethers.hexlify(burnAddress),20)
}

// TODO find better name since it get prevSpendAmount and nonce
export async function findLatestNonce({secret, tokenContract}) {
    //console.log(JSON.stringify(tokenContract))
    let nonce = -1n // TODO clean up this while loop so nonce starts at 0n. (for readability)
    let nullifier = undefined;
    let prevSpendAmount = 0n 
    while (nullifier !== "0x00") {
        nonce++;
        const nullifierId = hashNullifierId({nonce, secret})
        const remintedAmount = await tokenContract.remintedAmounts(nullifierId)
        prevSpendAmount += remintedAmount
        nullifier = ethers.toBeHex(await tokenContract.partialNullifiers(nullifierId))
        console.log({nullifier, nonce, prevSpendAmount})
    }
    return {nonce, prevSpendAmount}
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
 *          nullifier: ethers.BytesLike, 
 *          nullifierId: ethers.BytesLike,
 *          prevNullifierId: ethers.BytesLike, 
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
export async function getRemintProofData({contractAddress, burnAddress,withdrawAmount, blockNumber,secret, provider = provider}) {
    // contract data
    const tokenContract = new ethers.Contract(contractAddress, abi, provider)
    const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    const {nonce, prevSpendAmount} = await findLatestNonce({secret, tokenContract})

    // nullifiers
    const nullifier = hashNullifier({amount: prevSpendAmount + withdrawAmount,nonce,secret})
    const nullifierId = hashNullifierId({nonce,secret})
    const prevNullifierId = hashNullifierId({nonce: nonce-1n,secret})

    
    // storage proofs
    console.log("getting balance merkle proof")
    const balancesStateProof = await getStateProofOfMapping({contractAddress, key:burnAddress, keyType:"address", slot:BALANCES_SLOT,blockNumber, provider})
    console.log("getting nullifier merkle proof")
    const prevNullifierStateProof = await getStateProofOfMapping({contractAddress, key:prevNullifierId, keyType:"bytes32", slot:NULLIFIERS_SLOT,blockNumber, provider})
    
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
            nullifier, 
            nullifierId,
            prevNullifierId, 
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
 *          nullifier: ethers.BytesLike,
 *          nullifier_id: ethers.BytesLike,
 *          storage_root: ethers.BytesLike,
 *          secret: ethers.BytesLike,
 *          burned_balance: number[],
 *          nonce: ethers.BytesLike,
 *          prev_nullifier_id: ethers.BytesLike,
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
export async function getProofInputs({contractAddress, blockNumber,withdrawAmount,remintAddress, secret, provider, maxHashPathLen=MAX_HASH_PATH_SIZE, maxRlplen=MAX_RLP_SIZE}) {
 
    
    const burnAddress = hashBurnAddress({secret})
    const proofData = await getRemintProofData({contractAddress,burnAddress, withdrawAmount,blockNumber:Number(blockNumber),secret, provider})
    const storageRoot = proofData.stateProofData.balancesStateProof.accountProof.accountPreimage.storageRoot
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
            nullifier: nullifier,
            nullifier_id: nullifierId,
            //block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x)),
            storage_root: storageRoot,
            //--------------------


            // --private inputs--
            secret: ethers.toBeHex(secret),
            burned_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
            nonce: ethers.toBeHex(nonce),
            prev_nullifier_id: ethers.toBeHex(prevNullifierId),
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
    let nullifier: Field = ${proofData.nullifierData.nullifier};
    let nullifier_id: Field = ${proofData.nullifierData.nullifierId};
    let block_hash: [u8; 32] = [${paddArray([...ethers.toBeArray(proofData.stateProofData.block.hash)],32,0,true).map((x)=>ethers.toBeHex(x))}];
    
    //-----private inputs -----
    let secret: Field  = ${ethers.toBeHex(secret)};
    let burned_balance: [u8; 32]  = [${paddArray([...ethers.toBeArray(proofData.amounts.burnedTokenBalance)],32,0,true).map((x)=>ethers.toBeHex(x))}];
    let nonce: Field = ${proofData.nullifierData.nonce};
    let prev_nullifier_id: Field = ${proofData.nullifierData.prevNullifierId};
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
        nullifier,
        nullifier_id,
        block_hash,
        //-----private inputs -----
        secret,
        burned_balance,
        nonce,
        prev_nullifier_id,
        prev_spend_amount,
        burn_addr_storage_proof,
        prev_nullifier_storage_proof,
        contract_data,
    );
}
`
    return`
#[test]
fn test_main() {
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [${paddArray(hashPaths.accountProof.hashPath, maxHashPathLen, 0,false)}],
                leaf_type: ${hashPaths.accountProof.leafNode.type},
                node_types: [${paddArray(hashPaths.accountProof.nodeTypes, maxHashPathLen, 0,false)}],
                real_hash_path_len: ${hashPaths.accountProof.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.accountProof.leafNode.hashPathBools.slice(0,hashPaths.accountProof.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
            storage_proof: Hash_path_proof {
                hash_path: [${paddArray(hashPaths.storageProof.hashPath, maxHashPathLen, 0,false)}],
                leaf_type: ${hashPaths.storageProof.leafNode.type},
                node_types: [${paddArray(hashPaths.storageProof.nodeTypes, maxHashPathLen,  0,false)}],
                real_hash_path_len: ${hashPaths.storageProof.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.storageProof.leafNode.hashPathBools.slice(0,hashPaths.storageProof.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
        },
            contract_balance: ${contractBalance},
            header_rlp:[${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,maxRlplen))]}],
            header_rlp_len:${ethers.toBeArray(headerRlp).length},
            nonce_codesize_0:${hashPaths.accountProof.leafNode.valuePreimage[0]},
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
        console.log(formatTest({proofData, remintAddress, withdrawAmount, secret}))
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