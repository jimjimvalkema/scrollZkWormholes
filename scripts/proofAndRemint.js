
//hardhat
import "@nomicfoundation/hardhat-toolbox"
import { vars } from "hardhat/config.js"

//noir
// import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
// import { Noir } from '@noir-lang/noir_js';
// import { Barretenberg } from '@aztec/bb.js';

import { compile, createFileManager } from "@noir-lang/noir_wasm";
import { UltraHonkBackend, UltraPlonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
// import initNoirC from "@noir-lang/noirc_abi";
// import initACVM from "@noir-lang/acvm_js";
// import acvm from "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url";
// import noirc from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url";
// await Promise.all([initACVM(fetch(acvm)), initNoirC(fetch(noirc))]);

// other
import { ethers } from 'ethers';
import { poseidon1, poseidon2 } from "poseidon-lite";
import os from 'os';

// project imports
import { getProofInputs,getSafeRandomNumber,hashBurnAddress, paddArray } from "./getProofInputs.js"
import remintProverCircuit from '../circuits/remintProver/target/remintProver.json'  with { type: "json" }; //assert {type: 'json'};
import storageRootProverCircuit from '../circuits/storageRootProver/target/storageRootProver.json'  with { type: "json" }; //assert {type: 'json'};

//---- node trips up on the # in the file name. This is a work around----
//import {tokenAbi } from "../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json" assert {type: 'json'};
import fs from "fs/promises";
import path from 'path';
import { fileURLToPath } from 'url';
import Ethers from "@typechain/ethers-v6";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const tokenAbi = JSON.parse(await fs.readFile(__dirname + "/../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json", "utf-8")).abi
const remintVerifierAbi = JSON.parse(await fs.readFile(__dirname + "/../ignition/deployments/chain-534351/artifacts/VerifiersModule#RemintVerifier.json", "utf-8")).abi
const storageRootVerifierAbi = JSON.parse(await fs.readFile(__dirname + "/../ignition/deployments/chain-534351/artifacts/VerifiersModule#StorageRootVerifier.json", "utf-8")).abi
//--------------------------

//const smolVerifierAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/VerifiersModule#SmolVerifier.json", "utf-8")).abi

// --------------contract config---------------
// TODO make these public vars of the contract and retrieve them that way
const MAX_HASH_PATH_SIZE = 32;//248; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650

const MAX_HASH_PATH_SIZE_STORAGE_PROVER = 64;//should be 248 but wasm can only do 4gb ram;//this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE_STORAGE_PROVER = 850
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256

async function mint({ to, amount, contract }) {
    const mintTx = await contract.mint(to, amount)
    return mintTx
}

async function burn({ secret, amount, contract }) {
    const burnAddress = ethers.toBeHex(poseidon1([secret])).slice(0, 2 + 40) // take only first 20 bytes (because eth address are 20 bytes)
    const burnTx = await contract.transfer(burnAddress, amount)
    return { burnTx, burnAddress }
}
/**
 * @typedef {import("@noir-lang/noir_js").CompiledCircuit} CompiledCircuit 
 * @param {{
 *      noirjsInputs,
 *      circuit: CompiledCircuit, 
 *      contractDeployerWallet: ethers.Contract 
 * }} param0 
 * @typedef {import("@noir-lang/types").ProofData} ProofData
 * @returns {Promise<ProofData>} proof
 */
async function createRemintProof({ noirjsInputs, circuit = remintProverCircuit, contractDeployerWallet }) {
    // const backend = new BarretenbergBackend(circuit);
    // const noir = new Noir(circuit, backend)

    // // pre noirjs 0.31.0 \/
    // //const proof = await noir.generateProof(proofInputsNoirJs);
    // const { witness } = await noir.execute(proofInputsNoirJs);
    // const noirexcute =  await noir.execute(proofInputsNoirJs);
    // console.log({noirexcute})
    // const proof = await backend.generateProof(witness);

    // //TODO remove this debug

    // // pre noirjs 0.31.0 \/
    // //const verified = await noir.verifyProof(proof)
    // const verified = await backend.verifyProof(proof)
    // console.log({ verified })
    const noir = new Noir(circuit);
    //console.log({circuit})
    console.dir({remintProver: noirjsInputs},{depth:null})
    console.log(`generating remint proof with ${os.cpus().length} cores `)
    const backend = new UltraPlonkBackend(circuit.bytecode,  { threads:  os.cpus().length });
    const { witness } = await noir.execute(noirjsInputs);
    const proof = await backend.generateProof(witness);
    const verifiedByJs = await backend.verifyProof(proof);
    console.log("remintProof: ",{ verifiedByJs })

    const remintVerifierAddress = await contractDeployerWallet.remintVerifier()
    const remintVerifier = new ethers.Contract(remintVerifierAddress, remintVerifierAbi,contractDeployerWallet.runner.provider);
    const verifiedOnVerifierContract = await remintVerifier.verify(proof.proof, proof.publicInputs)
    console.log("remintProof: ", {verifiedOnVerifierContract})
    console.log({proof})

    return proof 
}



async function setTrustedStorageRoot({ storageRoot, blockNumber, contract }) {
    // @workaround
    // workaround since BLOCKHASH opcode is nerfed: https://docs.scroll.io/en/developers/ethereum-and-scroll-differences/#evm-opcodes
    const setBlockHashTx = await contract.setTrustedStorageRoot(storageRoot, blockNumber);
    return setBlockHashTx
}

async function remint({ to, amount, blockNumber,nullifierKey,nullifierValue, snarkProof, contract }) {
    // verify on chain and reMint!
    const remintTx = await contract.reMint(to, amount, blockNumber,nullifierKey,nullifierValue, snarkProof)
    return remintTx
}

function printTestFileInputs({ proofData, secret,withdrawAmount, recipientWallet, maxHashPathSize = MAX_HASH_PATH_SIZE, maxRlpSize = MAX_RLP_SIZE }) {
    // TODO update the files instead of logging 
    // console.log("------test main.nr--------------------------------------")
    // console.log(formatTest({proofData, remintAddress: recipientWallet, withdrawAmount, secret}))
    // console.log("--------------------------------------------------------\n")

    // console.log("------Prover.toml---------------------------------------")
    // console.log(formatToTomlProver(
    //     proofInputs.blockData.block,
    //     proofInputs.blockData.headerRlp,
    //     recipientWallet.address,
    //     secret,
    //     proofInputs.proofData.burnedTokenBalance,
    //     proofInputs.proofData.contractBalance,
    //     proofInputs.proofData.hashPaths,
    //     maxHashPathSize,
    //     maxRlpSize
    // ).toString())
    // console.log("--------------------------------------------------------\n")
}

/**
 * 
 * @typedef {import('./getProofInputs.js').RemintProofData} RemintProofData
 * @param {RemintProofData} proofData 
 * @param {ethers.Contract} tokenContract 
 */
async function verifyStorageRootOffchain({proofData, tokenContract,storageRootProverCircuit=storageRootProverCircuit, maxHashPathSize=MAX_HASH_PATH_SIZE_STORAGE_PROVER, maxRlpSize=MAX_RLP_SIZE_STORAGE_PROVER}) {
    //proofData unpacking
    const storageRoot = proofData.stateProofData.storageRoot
    const blockHash = proofData.stateProofData.block.hash
    const contractAddress = tokenContract.target
    
    const nonceCodesize0 = proofData.stateProofData.balancesStateProof.accountProof.leafNode.valuePreimage[0]
    const accountPreimage = proofData.stateProofData.balancesStateProof.accountProof.accountPreimage

    const accountProof = proofData.stateProofData.balancesStateProof.accountProof
    
    const rlp = proofData.stateProofData.rlp

    //noirjs formatting
    const noirjsInput = {
        storage_root: storageRoot,                                                          //pub Field,
        block_hash: paddArray([...ethers.toBeArray(blockHash)], 32, 0, true),               //pub [u8;32],
        padded_contract: paddArray([...ethers.toBeArray(contractAddress)], 32, 0, false),   //pub [u8; 32], 
        
        account_preimage: {                                                                 //Account_preimage_excl_storage,
            nonce_codesize_0: nonceCodesize0,                                               //Field,
            balance: accountPreimage.balance,                                               //Field,
            compressed_keccak_code_hash: accountPreimage.compressedKeccakCodehash,          //Field,
            poseidon_code_hash: accountPreimage.poseidonCodeHash                            //Field
        },

        account_proof: {                                                                    //Hash_path_proof<MAX_HASH_PATH_SIZE>,
            hash_path: paddArray(accountProof.hashPath,maxHashPathSize,"0x0",false),        //[Field;N],
            node_types: paddArray(accountProof.nodeTypes,maxHashPathSize,0,false),      //[Field;N],
            leaf_type: accountProof.leafNode.type,                                          //Field,
            real_hash_path_len:  accountProof.hashPath.length,                              //u32,
            hash_path_bools: paddArray(                                                     //[bool;N]
                accountProof.leafNode.hashPathBools.slice(0, accountProof.hashPath.length).reverse(), //TODO whack do this at the decode proof in the lob somehow
                maxHashPathSize,
                false,
                false
            )                                                                              
        },

        header_rlp: paddArray([...ethers.toBeArray(rlp)], maxRlpSize, "0x0", false),            //[u8; MAX_RLP_SIZE],
        header_rlp_len: ethers.toBeArray(rlp).length                                                          //u32,
    }
    console.dir({storageRootVerifier: {noirjsInput}},{depth:null})
    const noir = new Noir(storageRootProverCircuit);
    //console.log({circuit})
    console.log(`generating storageRoot proof with ${os.cpus().length} cores `)
    const backend = new UltraPlonkBackend(storageRootProverCircuit.bytecode,  { threads:  os.cpus().length });
    const { witness } = await noir.execute(noirjsInput);
    const proof = await backend.generateProof(witness);
    const verifiedByJs = await backend.verifyProof(proof);
    console.log("storageRoot verified in noirjs: ",{ verifiedByJs })

    const storageRootVerifier = new ethers.Contract(await tokenContract.storageRootVerifier(),storageRootVerifierAbi, tokenContract.runner.provider)
    const publicInputs = await tokenContract._formatPublicStorageRootInputs(storageRoot, blockHash, tokenContract.target)
    // console.log({proof, publicInputs})
    // console.log({proof: ethers.hexlify(proof.proof), publicInputs: [...publicInputs]})
    const verifiedOnVerifierContract = await storageRootVerifier.verify(ethers.hexlify(proof.proof),  [...publicInputs])
    console.log("storageRoot Proof: ",{verifiedOnVerifierContract}, "public inputs from '_formatPublicStorageRootInputs()' ")
}

async function main() {
    const CONTRACT_ADDRESS = "0x6A0e54612253d97Fd2c3dbb73BDdBAFfca531A9B"
    // --------------

    // --------------provider---------------
    const PROVIDERURL = "https://sepolia-rpc.scroll.io/"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    // --------------

    // --------------wallet config---------------
    
    const RPIVATE_KEY = vars.get("PRIVATE_KEY");
    const RECIPIENT_PRIVATE_KEY = vars.get("RECIPIENT_PRIVATE_KEY")
    // connect contracts
    const deployerWallet = new ethers.Wallet(RPIVATE_KEY, provider)
    const recipientWallet = new ethers.Wallet(RECIPIENT_PRIVATE_KEY, provider)
    const RECIPIENT_ADDRESS = recipientWallet.address
    const contractDeployerWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, deployerWallet);
    const contractRecipientWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, recipientWallet);
    // --------------


    //---------------burn -------------------
    // mint fresh tokens (normal mint)
    const burnAmount =      420000000000000000000n
    const remintAmount =    10000000000000000000n //-1n because there is a off by one error in the circuit which burns 1 wei
    const secret = 13093675745686700816186364422135239860302335203703094897030973687686916798500n//getSafeRandomNumber();
    const burnAddress = hashBurnAddress({secret})

    //mint
    const mintTx = await mint({ to: deployerWallet.address, amount: burnAmount, contract: contractDeployerWallet })
    console.log({ mintTx: (await mintTx.wait(1)).hash })
    
    // burn
    const { burnTx } = await burn({ secret, amount: burnAmount, contract: contractDeployerWallet })
    console.log({ burnAddress, burnTx: (await burnTx.wait(3)).hash }) // could wait less confirmation but

    // get storage proof
    const blockNumber = BigInt(await provider.getBlockNumber("latest"))
    // check if address and prevNullifier exist inside getProofInputs otherwise you get a merkle proof bad err
    const proofInputs = await getProofInputs({
        contractAddress: CONTRACT_ADDRESS, 
        blockNumber: blockNumber, 
        withdrawAmount: remintAmount, 
        remintAddress: recipientWallet.address, 
        secret: secret, 
        provider: provider, 
        maxHashPathSize: MAX_HASH_PATH_SIZE, 
        maxRlpSize: MAX_RLP_SIZE
    })


    // console.log("------------proof input json----------------")
    // console.dir({ noirJsInputs: proofInputs.noirJsInputs }, { depth: null }) 
    // //console.log(JSON.stringify(proofInputs.noirJsInputs, null, 2) )

    // console.log("---------------------------------------")
    //printTestFileInputs({proofData: proofInputs.proofData, secret,recipientWallet: recipientWallet.address, withdrawAmount: remintAmount})

    // get snark proof
    const proof = await createRemintProof({ noirjsInputs: proofInputs.noirJsInputs, circuit: remintProverCircuit, contractDeployerWallet })


    // this is to pretent that scroll actually made a proper BLOCKHASH opcode
    await verifyStorageRootOffchain({
        proofData:proofInputs.proofData , 
        tokenContract: contractDeployerWallet,
        storageRootProverCircuit, 
        maxHashPathSize: MAX_HASH_PATH_SIZE_STORAGE_PROVER, 
        maxRlpSize: MAX_RLP_SIZE_STORAGE_PROVER
    })

    //set trusted storageRoot (workaround for scroll missing BLOCKHASH opcode)
    const storageRoot = proofInputs.proofData.stateProofData.storageRoot
    const setStorageRootTx = await setTrustedStorageRoot({storageRoot, blockNumber, contract: contractDeployerWallet})
    console.log({
        setStorageRootTx: (await setStorageRootTx.wait(2)).hash,
        blockHash: proofInputs.blockData.block.hash,
        blockNumber,
        storageRoot
    })

    //remint
    const remintInputs = {
        to: RECIPIENT_ADDRESS,
        amount: remintAmount,
        blockNumber, //blockNumber: BigInt(proofInputs.blockData.block.number),
        nullifierKey: proofInputs.proofData.nullifierData.nullifierKey,
        nullifierValue: proofInputs.proofData.nullifierData.nullifierValue,
        snarkProof: ethers.hexlify(proof.proof),
    }
    
    console.log("------------remint tx inputs----------------")
    console.log("reminting with call args:")
    console.log({remintInputs})
    console.log("---------------------------------------")
    const remintTx = await remint({ ...remintInputs, contract: contractRecipientWallet })
    console.log({ remintTx: (await remintTx.wait(1)).hash })
    console.log({ burnAddress, secret: secret})


}
await main()
// idk its not stopping on its own prob wasm thing?
process.exit();