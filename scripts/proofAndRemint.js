import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import {getProofData, getProofInputsObj, formatToTomlProver} from "./getProofInputs.js"
import fs from "fs/promises";

import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json'  assert {type: 'json'};

// the # in the file name trips node up when using import
import path from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';
import "@nomicfoundation/hardhat-toolbox"
import { vars } from "hardhat/config.js"
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const tokenAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json", "utf-8")).abi
//const smolVerifierAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/VerifiersModule#SmolVerifier.json", "utf-8")).abi

const CONTRACT_ADDRESS = "0xF32F3F10B113f2A89C5FfCF87E4F283ebA849a5e"
const RECIPIENT_ADDRESS = "0x6D7e0B7e46dAa71862D810784E06f5Ed29cb7776" 
const RPIVATE_KEY = vars.get("PRIVATE_KEY");
const PROVIDERURL = "https://scroll-sepolia.drpc.org"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)
const wallet = new ethers.Wallet( RPIVATE_KEY, provider)
const contract = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, wallet);

//const VerifierContract = new ethers.Contract("0xC66B04bdD1Fc7d41fbfB5BA5180227C35e18e414", smolVerifierAbi, provider);

const tx1 =  await contract.mint("0x15e57b5244f1786e69d887cf6ebc5e2b25f3fc0b", 420000000000000000000n)
await tx1.wait(3)

// get proof
const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend)
//scroll
const {block, secret,burnedTokenBalance, contractBalance , hashPaths, burnAddress}  = await getProofData(CONTRACT_ADDRESS,await provider.getBlockNumber("latest"), provider)
const input =  await getProofInputsObj(block, RECIPIENT_ADDRESS, secret,burnedTokenBalance, contractBalance , hashPaths, provider)
const toml = await formatToTomlProver(block, RECIPIENT_ADDRESS,secret,burnedTokenBalance, contractBalance, hashPaths, provider, burnAddress)
console.log({toml})
console.log({input})
const proof = await noir.generateProof(input);
const verified = await noir.verifyProof(proof)
console.log({verified})


//submit proof

// const test = await contract.mint("0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7", 1n)
// console.log(test.wait(1))

// const signer = wallet.
console.log({RECIPIENT_ADDRESS,burnedTokenBalance, blockNumber: block.number, proof:  ethers.hexlify(proof.proof), publicInputs:  proof.publicInputs})
//const tx = await contract.reMint(RECIPIENT_ADDRESS,burnedTokenBalance, BigInt(block.number), ethers.hexlify(proof.proof))
const tx = await contract.reMintTest(RECIPIENT_ADDRESS,burnedTokenBalance, BigInt(block.number), proof.proof, proof.publicInputs)
console.log(await tx.wait(1))
// idk its not stopping on its own prob wasm thing?
process.exit();