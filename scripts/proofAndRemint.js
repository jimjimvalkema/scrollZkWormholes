import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import {getProofData, getProofInputsObj, formatToTomlProver} from "./getProofInputs.js"
import { poseidon1} from "poseidon-lite";
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

const CONTRACT_ADDRESS = "0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f"
const RECIPIENT_ADDRESS = "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54" 
const RPIVATE_KEY = vars.get("PRIVATE_KEY");
const RECIPIENT_PRIVATE_KEY = vars.get("RECIPIENT_PRIVATE_KEY")
const PROVIDERURL = "https://scroll-sepolia.drpc.org"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)
const deployerWallet = new ethers.Wallet( RPIVATE_KEY, provider)
const recipientWallet = new ethers.Wallet( RECIPIENT_PRIVATE_KEY, provider)
const contractDeployerWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, deployerWallet);
const contractRecipientWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, recipientWallet);

//const VerifierContract = new ethers.Contract("0xC66B04bdD1Fc7d41fbfB5BA5180227C35e18e414", smolVerifierAbi, provider);
// burn addy =0x15e57b5244f1786e69d887cf6ebc5e2b25f3fc0b

// mint fresh tokens (normal mint)
const burnValue = 420000000000000000000n
const mintTx =  await contractDeployerWallet.mint(deployerWallet.address, burnValue)
await mintTx.wait(3)
console.log({mintTx: await mintTx.wait(3)})

// burn
const secret = 123
const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([123])).slice(0,20))
console.log({burnAddress})
const burnTx = await contractDeployerWallet.transfer(burnAddress, burnValue)
console.log({burnTx: await burnTx.wait(3)})

// get storage proof
const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend)
const {block,burnedTokenBalance, contractBalance , hashPaths}  = await getProofData(CONTRACT_ADDRESS,burnAddress,await provider.getBlockNumber("latest"), provider)
const input =  await getProofInputsObj(block, RECIPIENT_ADDRESS, secret,burnedTokenBalance, contractBalance , hashPaths, provider)
const toml = await formatToTomlProver(block, RECIPIENT_ADDRESS,secret,burnedTokenBalance, contractBalance, hashPaths, provider, burnAddress)

console.log("------------prover toml----------------")
console.log(toml)
console.log("---------------------------------------")
console.log("------------proof input json----------------")
console.log({input})
console.log("---------------------------------------")

// get snark proof
const proof = await noir.generateProof(input);
const verified = await noir.verifyProof(proof)
console.log({verified})


const remintInputs = {to:RECIPIENT_ADDRESS,amount:burnedTokenBalance, blockNum: BigInt(block.number), snarkProof:  ethers.hexlify(proof.proof)}
console.log("------------remint tx inputs----------------")
console.log({remintInputs})
console.log("---------------------------------------")

// @workaround
// workaround since BLOCKHASH opcode is nerfed: https://docs.scroll.io/en/developers/ethereum-and-scroll-differences/#evm-opcodes
const setBlockHashTx = await contractDeployerWallet.setBlockHash(block.hash, block.number);
console.log({setBlockHashTx: await setBlockHashTx.wait(3)})

const remintTx = await contractRecipientWallet.reMint(remintInputs.to,remintInputs.amount, remintInputs.blockNum, remintInputs.snarkProof)
console.log({remintTx: await remintTx.wait(3)})


// idk its not stopping on its own prob wasm thing?
process.exit();