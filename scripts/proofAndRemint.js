
//hardhat
import "@nomicfoundation/hardhat-toolbox"
import { vars } from "hardhat/config.js"

//noir
import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';

// other
import { ethers } from 'ethers';
import { poseidon1, poseidon2 } from "poseidon-lite";

// project imports
import { formatTest, getProofInputs, formatToTomlProver,getSafeRandomNumber } from "./getProofInputs.js"
import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json'  assert {type: 'json'};

//---- node trips up on the # in the file name. This is a work around----
//import {tokenAbi } from "../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json" assert {type: 'json'};
import fs from "fs/promises";
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const tokenAbi = JSON.parse(await fs.readFile(__dirname + "/../ignition/deployments/chain-534351/artifacts/TokenModule#Token.json", "utf-8")).abi
//--------------------------

//const smolVerifierAbi = JSON.parse(await fs.readFile(__dirname+"/../ignition/deployments/chain-534351/artifacts/VerifiersModule#SmolVerifier.json", "utf-8")).abi

// --------------contract config---------------
// TODO make these public vars of the contract and retrieve them that way
const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650
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

async function creatSnarkProof({ proofInputsNoirJs, circuit = circuit }) {
    const backend = new BarretenbergBackend(circuit);
    const noir = new Noir(circuit, backend)

    // pre noirjs 0.31.0 \/
    //const proof = await noir.generateProof(proofInputsNoirJs);
    const { witness } = await noir.execute(proofInputsNoirJs);
    const noirexcute =  await noir.execute(proofInputsNoirJs);
    console.log({noirexcute})
    const proof = await backend.generateProof(witness);

    //TODO remove this debug

    // pre noirjs 0.31.0 \/
    //const verified = await noir.verifyProof(proof)
    const verified = await backend.verifyProof(proof)
    console.log({ verified })

    return proof 
}



async function setBlockHash({ blockHash, blockNumber, contract }) {
    // @workaround
    // workaround since BLOCKHASH opcode is nerfed: https://docs.scroll.io/en/developers/ethereum-and-scroll-differences/#evm-opcodes
    const setBlockHashTx = await contract.setBlockHash(blockHash, blockNumber);
    return setBlockHashTx
}

async function remint({ to, amount, blockNumber,nullifier, snarkProof, contract }) {
    // verify on chain and reMint!
    const remintTx = await contract.reMint(to, amount, blockNumber,nullifier, snarkProof)
    return remintTx
}

function printTestFileInputs({ proofInputs, secret, recipientWallet, maxHashPathSize = MAX_HASH_PATH_SIZE, maxRlpSize = MAX_RLP_SIZE }) {
    // TODO update the files instead of logging 
    console.log("------test main.nr--------------------------------------")
    console.log(formatTest(
        proofInputs.blockData.block,
        proofInputs.blockData.headerRlp,
        recipientWallet.address,
        secret,
        proofInputs.proofData.burnedTokenBalance,
        proofInputs.proofData.contractBalance,
        proofInputs.proofData.hashPaths,
        maxHashPathSize,
        maxRlpSize
    ))
    console.log("--------------------------------------------------------\n")

    // console.log("------Prover.toml---------------------------------------")
    console.log(formatToTomlProver(
        proofInputs.blockData.block,
        proofInputs.blockData.headerRlp,
        recipientWallet.address,
        secret,
        proofInputs.proofData.burnedTokenBalance,
        proofInputs.proofData.contractBalance,
        proofInputs.proofData.hashPaths,
        maxHashPathSize,
        maxRlpSize
    ).toString())
    console.log("--------------------------------------------------------\n")
}

async function main() {
    const CONTRACT_ADDRESS = "0xB10f8e42cBF1b2075d0447Cd40213c046DEB9940"
    // --------------

    // --------------provider---------------
    const PROVIDERURL = "https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    // --------------

    // --------------wallet config---------------
    const RECIPIENT_ADDRESS = "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54"
    const RPIVATE_KEY = vars.get("PRIVATE_KEY");
    const RECIPIENT_PRIVATE_KEY = vars.get("RECIPIENT_PRIVATE_KEY")
    // connect contracts
    const deployerWallet = new ethers.Wallet(RPIVATE_KEY, provider)
    const recipientWallet = new ethers.Wallet(RECIPIENT_PRIVATE_KEY, provider)
    const contractDeployerWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, deployerWallet);
    const contractRecipientWallet = new ethers.Contract(CONTRACT_ADDRESS, tokenAbi, recipientWallet);
    // --------------


    //---------------burn -------------------
    // mint fresh tokens (normal mint)
    const burnValue = 420000000000000000000n
    const secret = getSafeRandomNumber();

    //mint
    const mintTx = await mint({ to: deployerWallet.address, amount: burnValue, contract: contractDeployerWallet })
    console.log({ mintTx: (await mintTx.wait(1)).hash })

    // burn
    const { burnTx, burnAddress } = await burn({ secret, amount: burnValue, contract: contractDeployerWallet })
    console.log({ burnAddress, burnTx: (await burnTx.wait(3)).hash }) // could wait less confirmation but


    // get storage proof
    const blockNumber = BigInt(await provider.getBlockNumber("latest"))
    const proofInputs = await getProofInputs(CONTRACT_ADDRESS, blockNumber, recipientWallet.address, secret, provider, MAX_HASH_PATH_SIZE, MAX_RLP_SIZE)


    console.log("------------proof input json----------------")
    console.log({ noirJsInputs: proofInputs.noirJsInputs })
    console.log("---------------------------------------")
    //printTestFileInputs({proofInputs, secret,recipientWallet})

    // get snark proof
    const proof = await creatSnarkProof({ proofInputsNoirJs: proofInputs.noirJsInputs, circuit: circuit })
    console.log({proof})

    //set blockHash(workaroud)
    const blockHash = proofInputs.blockData.block.hash
    const setBlockHashTx = await setBlockHash({ blockHash, blockNumber, contract: contractDeployerWallet })
    console.log({
        setBlockHashTx: (await setBlockHashTx.wait(1)).hash,
        blockHash: proofInputs.blockData.block.hash,
        blockNumber: proofInputs.blockData.block.number
    })

    //remint
    const remintInputs = {
        to: RECIPIENT_ADDRESS,
        amount: proofInputs.proofData.burnedTokenBalance,
        blockNumber, //blockNumber: BigInt(proofInputs.blockData.block.number),
        nullifier: ethers.toBeHex(proofInputs.proofData.nullifier),
        snarkProof: ethers.hexlify(proof.proof),
        
    }
    console.log("------------remint tx inputs----------------")
    console.log({ remintInputs })
    console.log("---------------------------------------")
    const remintTx = await remint({ ...remintInputs, contract: contractRecipientWallet })
    console.log({ remintTx: (await remintTx.wait(1)).hash })


}
await main()
// idk its not stopping on its own prob wasm thing?
process.exit();