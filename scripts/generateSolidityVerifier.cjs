const util = require('util');
const {spawn, exec} = require('node:child_process');
const execProm = util.promisify(exec)
const fs = require("fs/promises");
const { ethers } = require('ethers');
const path = require( 'path');
const  {poseidon2}  = require("poseidon-lite-with-domain")
// const getProofInputsImportPromise =  import("./getProofInputs.js") // i hate this ffs
// const HASH_DOMAIN_ELEMS_BASE = 256;
// const HASH_DOMAIN_BYTE32     = 2 * HASH_DOMAIN_ELEMS_BASE;
const SOLIDITY_VERSION = "0.8.28"

async function generateSolidityVerifier(circuitRootFolder, circuitName, verifierName, contractsRootFolder) {
    // const {paddArray} = await getProofInputsImportPromise;


    const lineReplacements = [
        {
            "original"      :`contract UltraVerifier is BaseUltraVerifier {`,
            "replacement"   :`contract ${verifierName} is BaseUltraVerifier {\n`
        },
        {
            "original"      :`pragma solidity`,
            "replacement"   :`pragma solidity ${SOLIDITY_VERSION};\n`
        }
    ]
    let command = `cd ${path.normalize(circuitRootFolder)}; nargo compile; bb write_vk -b ./target/${circuitName}.json; bb contract;`
    //const command = `cd ${path.normalize(filePath+"/../../")}; nargo compile; bb write_vk_ultra_honk -b ./target/zkwormholesEIP7503.json; bb contract_ultra_honk;`
    console.log(`generating verifier: ${verifierName}`,{command})
    await execProm(command)


    const solidityVerifierPath = circuitRootFolder+"/target/contract.sol"
    await new Promise(resolve => setTimeout(resolve, 10000));

    // command = `await fs.rename(${path.normalize(solidityVerifierPath)}, ${path.normalize(contractsRootFolder)+`/${verifierName}.sol`})`
    const verifierContractDestination = path.normalize(contractsRootFolder)+`/${verifierName}.sol`
    console.log("moving file",{solidityVerifierPath, verifierContractDestination})
    await fs.rename(path.normalize(solidityVerifierPath), verifierContractDestination)
    await new Promise(resolve => setTimeout(resolve, 10000));

    await lineReplacer(verifierContractDestination, lineReplacements)



    console.log("succes")
    return true
}

async function lineReplacer(filePath, lineReplacements ) {
    const file = await fs.open(filePath, "r")
    let newFile = ""

    for await (const line of file.readLines()) {
        //if (line.startsWith("contract HonkVerifier is IVerifier")) {  
        const replacement = lineReplacements.find((replacement)=>line.startsWith(replacement.original))
        if (replacement) { 
            newFile += replacement.replacement
            console.log({replacement})
        } else {
            newFile += line+"\n"
        }
    }
    await file.close()
    await fs.writeFile(filePath, newFile);
}


module.exports = {
    generateSolidityVerifier
}