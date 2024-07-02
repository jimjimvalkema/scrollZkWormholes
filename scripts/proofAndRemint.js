import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import {getProofData, getProofInputsObj} from "./getProofInputs.js"
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

const CONTRACT_ADDRESS = "0x665337447B52FE31B715f616F94a30A1eA86770c"
const RECIPIENT_ADDRESS = "0x6D7e0B7e46dAa71862D810784E06f5Ed29cb7776" 
const RPIVATE_KEY = vars.get("PRIVATE_KEY");

// get proof
const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend)
//scroll
const PROVIDERURL = "https://scroll-sepolia.drpc.org"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)
const {block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, burnAddress}  = await getProofData(CONTRACT_ADDRESS,await provider.getBlockNumber("latest"), provider)
const input =  await getProofInputsObj(block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider)
const proof = await noir.generateProof(input);

//submit proof
const wallet = new ethers.Wallet( RPIVATE_KEY, provider)
const contract = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, wallet);

// const signer = wallet.
console.log({RECIPIENT_ADDRESS,burnedTokenBalance, blockNumber: block.number, proof:  ethers.hexlify(proof.proof)})
const tx = await contract.reMint(RECIPIENT_ADDRESS,burnedTokenBalance, block.number, ethers.hexlify(proof.proof))
console.log(await tx.wait(1))
// idk its not stopping on its own prob wasm thing?
process.exit();