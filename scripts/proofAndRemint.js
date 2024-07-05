
//hardhat
import "@nomicfoundation/hardhat-toolbox"
import { vars } from "hardhat/config.js"

//noir
import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';

// other
import { ethers } from 'ethers';
import { poseidon1} from "poseidon-lite";

// project imports
import {formatTest, getProofInputs, formatToTomlProver} from "./getProofInputs.js"
import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json'  assert {type: 'json'};
//---- node trips up on the # in the file name. This is a work around----
//import {tokenAbi } from "../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json" assert {type: 'json'};
import fs from "fs/promises";
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const tokenAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json", "utf-8")).abi
//const smolVerifierAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/VerifiersModule#SmolVerifier.json", "utf-8")).abi

// --------------contract config---------------
const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650
const CONTRACT_ADDRESS = "0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f"
const RECIPIENT_ADDRESS = "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54" 
// --------------

// --------------provider---------------
const PROVIDERURL = "https://scroll-sepolia.drpc.org"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)
// --------------

// --------------wallet config---------------
const RPIVATE_KEY = vars.get("PRIVATE_KEY");
const RECIPIENT_PRIVATE_KEY = vars.get("RECIPIENT_PRIVATE_KEY")
// conect contracts
const deployerWallet = new ethers.Wallet( RPIVATE_KEY, provider)
const recipientWallet = new ethers.Wallet( RECIPIENT_PRIVATE_KEY, provider)
const contractDeployerWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, deployerWallet);
const contractRecipientWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, recipientWallet);
// --------------


//---------------burn -------------------
// mint fresh tokens (normal mint)
const burnValue = 420000000000000000000n
const mintTx =  await contractDeployerWallet.mint(deployerWallet.address, burnValue)
await mintTx.wait(3)
console.log({mintTx: (await mintTx.wait(2)).hash})

// burn
const secret = 123
const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([123])).slice(0,20))
console.log({burnAddress})
const burnTx = await contractDeployerWallet.transfer(burnAddress, burnValue)
console.log({burnTx: (await burnTx.wait(2)).hash})

// get storage proof
const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend)
const blockNumber = await provider.getBlockNumber("latest")
const proofInputs = await getProofInputs(CONTRACT_ADDRESS,blockNumber,recipientWallet.address,secret,provider,MAX_HASH_PATH_SIZE,MAX_RLP_SIZE)

// TODO update the files instead of logging 
// console.log("------test main.nr--------------------------------------")
// console.log(formatTest(
//     proofInputs.blockData.block, 
//     proofInputs.blockData.headerRlp, 
//     recipientWallet.address, 
//     secret,
//     proofInputs.proofData.burnedTokenBalance, 
//     proofInputs.proofData.contractBalance , 
//     proofInputs.proofData.hashPaths,
//     MAX_HASH_PATH_SIZE,
//     MAX_RLP_SIZE
// ))
// console.log("--------------------------------------------------------\n")
// console.log("------Prover.toml---------------------------------------")
// console.log(formatToTomlProver(
//     proofInputs.blockData.block, 
//     proofInputs.blockData.headerRlp, 
//     recipientWallet.address, 
//     secret,
//     proofInputs.proofData.burnedTokenBalance, 
//     proofInputs.proofData.contractBalance , 
//     proofInputs.proofData.hashPaths,
//     MAX_HASH_PATH_SIZE,
//     MAX_RLP_SIZE
// ).toString())
// console.log("--------------------------------------------------------\n")
console.log("------------proof input json----------------")
console.log({noirJsInputs: proofInputs.noirJsInputs})
console.log("---------------------------------------")

// get snark proof
const proof = await noir.generateProof(proofInputs.noirJsInputs);
const verified = await noir.verifyProof(proof)
console.log({verified})




// @workaround
// workaround since BLOCKHASH opcode is nerfed: https://docs.scroll.io/en/developers/ethereum-and-scroll-differences/#evm-opcodes
const setBlockHashTx = await contractDeployerWallet.setBlockHash(proofInputs.blockData.block.hash, proofInputs.blockData.block.number);
console.log({
    setBlockHashTx: (await setBlockHashTx.wait(3)).hash,
    blockhash: proofInputs.blockData.block.hash,
    blockNumber: proofInputs.blockData.block.number
})

const remintInputs = {
    to:RECIPIENT_ADDRESS,
    amount:proofInputs.proofData.burnedTokenBalance, 
    blockNum: BigInt(proofInputs.blockData.block.number), 
    snarkProof:  ethers.hexlify(proof.proof)
}
console.log("------------remint tx inputs----------------")
console.log({remintInputs})
console.log("---------------------------------------")
// verify on chain and reMint!
const remintTx = await contractRecipientWallet.reMint(remintInputs.to,remintInputs.amount, remintInputs.blockNum, remintInputs.snarkProof)
console.log({remintTx: (await remintTx.wait(2)).hash})


// idk its not stopping on its own prob wasm thing?
process.exit();