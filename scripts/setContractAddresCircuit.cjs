const util = require('util');
const {spawn, exec} = require('node:child_process');
const execProm = util.promisify(exec)
const fs = require("fs/promises");
const { ethers } = require('ethers');
const path = require( 'path');
const  {poseidon2}  = require("../../lib/poseidon-lite-for-scroll/build/index.js")
const HASH_DOMAIN_ELEMS_BASE = 256;
const HASH_DOMAIN_BYTE32     = 2 * HASH_DOMAIN_ELEMS_BASE;
const SOLIDITY_VERSION = "0.8.23"

async function setContractCircuit(contract="0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7", filePath, solidityVerifierDestination, newContractName, provider) {
    const {compressedKeccakCodeHash, poseidonCodeHash} = await getCodeHashes(contract,provider)
    const paddedContractArr = [...ethers.toBeArray(contract), ...Array(32-20).fill(0)]
    

    const file = await fs.open(filePath, "r")
    let newFile = ""


    for await (const line of file.readLines()) {
        if (line.startsWith("global PADDED_CONTRACT_ADDRESS")) {   
            //TODO poseidon code hash compressed keccak code hash
            console.log(line)
            console.log(`global PADDED_CONTRACT_ADDRESS = [${paddedContractArr}];\n`)
            newFile += `global PADDED_CONTRACT_ADDRESS = [${paddedContractArr}];\n`
        } else if (line.startsWith("global POSEIDON_CODE_HASH =")) {
            console.log(line)
            console.log(`global POSEIDON_CODE_HASH = ${poseidonCodeHash};\n`)
            newFile += `global POSEIDON_CODE_HASH = ${poseidonCodeHash};\n`
        } else if (line.startsWith("global COMPRESSED_KECCAK_CODE_HASH =")) {
            console.log(line)
            console.log(`global COMPRESSED_KECCAK_CODE_HASH = ${compressedKeccakCodeHash};\n`)
            newFile += `global COMPRESSED_KECCAK_CODE_HASH = ${compressedKeccakCodeHash};\n`
        } else {
            newFile+=line+"\n"
        }
        
    }
    await file.close()
    await fs.writeFile(filePath, newFile);
    //console.log(`compiling solidity verifier at: ${filePath+"/../../"}`)
    await new Promise(resolve => setTimeout(resolve, 10000));
    const command = `cd ${path.normalize(filePath+"/../../")}; nargo compile; nargo codegen-verifier`
    console.log({command})
    await execProm(command)
    const solidityVerifierPath = filePath+"/../../contract/zkwormholesEIP7503/plonk_vk.sol"
    await new Promise(resolve => setTimeout(resolve, 10000));

    console.log(`await fs.rename(${path.normalize(solidityVerifierPath)}, ${path.normalize(solidityVerifierDestination)})`)
    await fs.rename(path.normalize(solidityVerifierPath), path.normalize(solidityVerifierDestination))
    await new Promise(resolve => setTimeout(resolve, 10000));

    await renameContract( path.normalize(solidityVerifierDestination), newContractName)
    console.log(`await renameContract(${path.normalize(solidityVerifierDestination)}, ${ newContractName})})`)

    //contract UltraVerifier is BaseUltraVerifier {
    console.log("succes")
    return true
}

async function main() {
    await setContract(process.argv[2])

}

async function renameContract(filePath, newName) {
    const file = await fs.open(filePath, "r")
    let newFile = ""

    for await (const line of file.readLines()) {
        if (line.startsWith("contract UltraVerifier is BaseUltraVerifier {")) {   
            //TODO poseidon code hash compressed keccak code hash
            console.log(line)
            console.log(`contract ${newName} is BaseUltraVerifier {\n`)
            newFile += `contract ${newName} is BaseUltraVerifier {\n`
        } else if (line.startsWith("pragma solidity")) {
            console.log(line)
            console.log(`pragma solidity ${SOLIDITY_VERSION};\n`)
            newFile += `pragma solidity ${SOLIDITY_VERSION};\n`
        }else {
            newFile+=line+"\n"
        }
        
    }
    await file.close()


    await fs.writeFile(filePath, newFile);
}
// main()

// silly ah way to do this
// TODO find a better method to get code hashes
async function getCodeHashes(contractAddress = "0x665337447B52FE31B715f616F94a30A1eA86770c",provider) {
    const blockNumber = await provider.getBlockNumber("latest")
    const blockNumberHex = "0x" + blockNumber.toString(16)
    const params = [contractAddress, [ethers.zeroPadBytes("0x00", 32)], blockNumberHex,]
    const proof = await provider.send('eth_getProof', params)
    const compKeccakPreImage = ["0x"+proof.keccakCodeHash.slice(2, 2+32), "0x"+proof.keccakCodeHash.slice(2+32, 2+64)]
    //console.log(compKeccakPreImage)
    //console.log({compKeccakPreImage})
    const codeHashes =  {
        compressedKeccakCodeHash: ethers.toBeHex(poseidon2(compKeccakPreImage, HASH_DOMAIN_BYTE32)),
        keccakCodeHash: proof.keccakCodeHash,
        poseidonCodeHash: proof.poseidonCodeHash
    }
    console.log({codeHashes})
    return codeHashes
    
}

module.exports = {
    setContractCircuit
}