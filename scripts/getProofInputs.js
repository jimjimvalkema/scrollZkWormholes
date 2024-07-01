const { ethers, N } = require("ethers");
const { poseidon1 } = require("poseidon-lite");
import * as fs from 'node:fs/promises';
import {getHashPathFromProof} from "../../scripts/decodeScrollProof"
import {createStoragePositionMapping, getBlockHeaderRlp} from "../../scripts/getScrollProof"
import { ZkTrieNode, NodeTypes, leafTypes } from "../../scripts/types/ZkTrieNode.js";

const MAX_HASH_PATH_SIZE = 248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

const abi = [
    "function balanceOf(address) view returns (uint)"
];



async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress, [storageKey], blockNumberHex,]
    const proof = await provider.send('eth_getProof', params)
    return proof
}

function paddArray(arr,len=32,filler=0, infront=true) {
    if (infront) {
        return [...Array(len-arr.length).fill(filler), ...arr]

    } else {
        return [ ...arr, ...Array(len-arr.length).fill(filler)]
    }
    

}

function asPaddedArray(value, len=32, infront=true) {
    const valueArr = [...ethers.toBeArray(value)]
    return paddArray(valueArr, len,0, infront)
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
async function formatToTomlProver(block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider) {
    const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return `block_hash = [${[...ethers.toBeArray(block.hash)].map((x)=>`"${x}"`)}] 
remint_address = "${remintAddress}"
secret = "${ethers.toBeHex(secret)}"
user_balance =  [${asPaddedArray(burnedTokenBalance, 32).map((x)=>`"${x}"`)}]

[storage_proof_data]
contract_balance = "${contractBalance}"
header_rlp =  [${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,MAX_RLP_SIZE))].map((x)=>`"${x}"`)}]
header_rlp_len = "${ethers.toBeArray(headerRlp).length}"
nonce_codesize_0 = "${hashPaths.account.leafNode.valuePreimage[0]}"

[storage_proof_data.hash_paths.account_proof]
hash_path = [${paddArray(hashPaths.account.hashPath, MAX_HASH_PATH_SIZE, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.account.leafNode.type}"
node_types = [${paddArray(hashPaths.account.nodeTypes, MAX_HASH_PATH_SIZE, 0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.account.hashPath.length}"` 
+
`\nhash_path_bools = [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, 0,false).map((x)=>`"${Number(x)}"`)}]`
+
`\n
[storage_proof_data.hash_paths.storage_proof]
hash_path = [${paddArray(hashPaths.storage.hashPath, MAX_HASH_PATH_SIZE, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.storage.leafNode.type}"
node_types = [${paddArray(hashPaths.storage.nodeTypes, MAX_HASH_PATH_SIZE,  0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.storage.hashPath.length}"`
+
`\nhash_path_bools =  [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false,false).map((x)=>`"${Number(x)}"`)}]`

}

export async function getProofData() {
    const secret = 123
    const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([123])).slice(0,20))
    console.log({burnAddress})
    const remintAddress = "0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7"
 

    //scroll
    const PROVIDERURL = "https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockNumber =  5093419//await provider.getBlockNumber("latest")

    //Token
    const contractAddress = "0x29d801Af49F0D88b6aF01F4A1BD11846f0c96672"

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


    const  block  =await provider.getBlock(blockNumber)
    const contractBalance = await provider.getBalance(contractAddress)
    return {block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider, burnAddress}
}

/**
 * 
 * @param {ethers.HexString} input 
 * @param {Number} bytes 
 * @returns 
 */
function splitBytes(input, len) {
    const regEx = new RegExp(`.{1,${2*len}}`, "g")
    return input.slice(2).match(regEx).map((x)=>"0x"+x)

}

export async function getProofInputsObj(block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider) {
    const split = (bytes)=>splitBytes(bytes,1);

    const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return {
        storage_proof_data: {
            hash_paths: {
                account_proof: {
                    hash_path: paddArray(hashPaths.account.hashPath, MAX_HASH_PATH_SIZE,  ethers.zeroPadBytes("0x00",32), false).map((x) => split(x)),
                    leaf_type:  split(ethers.toBeHex(hashPaths.account.leafNode.type)),
                    node_types: paddArray(hashPaths.account.nodeTypes, MAX_HASH_PATH_SIZE, 0, false),
                    real_hash_path_len:  split(ethers.toBeHex(hashPaths.account.hashPath.length)),
                    hash_path_bools: paddArray(hashPaths.account.leafNode.hashPathBools.slice(0, hashPaths.account.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false),
                },
                storage_proof: {
                    hash_path: paddArray(hashPaths.storage.hashPath, MAX_HASH_PATH_SIZE, ethers.zeroPadBytes("0x00",32), false).map((x) => split(x)),
                    leaf_type:  split(ethers.toBeHex(hashPaths.storage.leafNode.type)),
                    node_types: paddArray(hashPaths.storage.nodeTypes, MAX_HASH_PATH_SIZE, 0, false),
                    real_hash_path_len: split(ethers.toBeHex(hashPaths.storage.hashPath.length)),
                    hash_path_bools: paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0, hashPaths.storage.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false),

                },
            },
            contract_balance: split(ethers.toBeHex(contractBalance)),
            header_rlp: [...ethers.toBeArray(ethers.zeroPadBytes(headerRlp, MAX_RLP_SIZE))].map((x) => ethers.toBeHex(x)),
            header_rlp_len: ethers.toBeArray(headerRlp).length,
            nonce_codesize_0: split(hashPaths.account.leafNode.valuePreimage[0]),
        },
        secret: split(ethers.toBeHex(secret)),
        remint_address: split(remintAddress),
        user_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
        block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x))
    }
}

async function formatTest(block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider) {
    const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return`
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [${paddArray(hashPaths.account.hashPath, MAX_HASH_PATH_SIZE, 0,false)}],
                leaf_type: ${hashPaths.account.leafNode.type},
                node_types: [${paddArray(hashPaths.account.nodeTypes, MAX_HASH_PATH_SIZE, 0,false)}],
                real_hash_path_len: ${hashPaths.account.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
            storage_proof: Hash_path_proof {
                hash_path: [${paddArray(hashPaths.storage.hashPath, MAX_HASH_PATH_SIZE, 0,false)}],
                leaf_type: ${hashPaths.storage.leafNode.type},
                node_types: [${paddArray(hashPaths.storage.nodeTypes, MAX_HASH_PATH_SIZE,  0,false)}],
                real_hash_path_len: ${hashPaths.storage.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
        },
            contract_balance: ${contractBalance},
            header_rlp:[${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,MAX_RLP_SIZE))]}],
            header_rlp_len:${ethers.toBeArray(headerRlp).length},
            nonce_codesize_0:${hashPaths.account.leafNode.valuePreimage[0]},
        };


    let secret = ${secret};

    let remint_address = ${remintAddress};
    let user_balance = [${asPaddedArray(burnedTokenBalance, 32)}];
    let block_hash =  [${[...ethers.toBeArray(block.hash)]}];`
}


async function main() {
    // const secret = 123
    // const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([123])).slice(0,20))
    // console.log({burnAddress})
    // const remintAddress = "0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7"
 

    // //scroll
    // const PROVIDERURL = "https://scroll-sepolia.drpc.org"
    // const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    // const blockNumber =  5093419//await provider.getBlockNumber("latest")

    // //Token
    // const contractAddress = "0x29d801Af49F0D88b6aF01F4A1BD11846f0c96672"

    // const tokenContract = new ethers.Contract(contractAddress, abi, provider)

    // const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    // //slot pos for balances of weth contract
    // const mappingSlot = "0x00"
    // //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    // const storageKey = createStoragePositionMapping(burnAddress, "address", mappingSlot)
    // const proof = await getProof(contractAddress, storageKey, blockNumber, provider)
    // await Bun.write('zkwormholesExample/scripts/out/proof.json', JSON.stringify(proof,null,2))
    
    // const hashPaths = {
    //     "account": getHashPathFromProof(proof.accountProof),
    //     "storage": getHashPathFromProof(proof.storageProof[0].proof)
    // }


    // const  block  =await provider.getBlock(blockNumber)
    // const contractBalance = await provider.getBalance(contractAddress)
    const {block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider, burnAddress} = await getProofData()
    const blockNumber = block.number
    const toml = await formatToTomlProver(block, remintAddress,secret,burnedTokenBalance, contractBalance, hashPaths, provider, burnAddress)
    await Bun.write('zkwormholesExample/scripts/out/unformattedProofInputs.json',JSON.stringify({secret, burnAddress, blockNumber, hashPaths},null,2))

    await Bun.write('zkwormholesExample/circuit/Prover.toml', toml)
    console.log({blockHash:block.hash, stateroot: block.stateRoot})
    console.log(await formatTest(block, remintAddress,secret,burnedTokenBalance, contractBalance, hashPaths, provider))
}

main()