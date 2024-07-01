const util = require('util');
const {spawn, exec} = require('node:child_process');
const execProm = util.promisify(exec)
const fs = require("fs/promises");
const { ethers } = require('ethers');

async function setContract(contract="0x794464c8c91A2bE4aDdAbfdB82b6db7B1Bb1DBC7", filePath='circuit/src/main.nr') {
    const paddedContractArr = [...ethers.toBeArray(contract), ...Array(32-20).fill(0)]
    

    const file = await fs.open(filePath, "r")
    let newFile = ""

    for await (const line of file.readLines()) {
        if (line.startsWith("global PADDED_CONTRACT_ADDRESS")) {   
            //TODO poseidon code hash compressed keccak code hash
            newFile += `global PADDED_CONTRACT_ADDRESS = [${paddedContractArr}];\n`
        } else {
            newFile+=line+"\n"
        }
        
    }
    await file.close()


    await fs.writeFile(filePath, newFile);
    await execProm("cd circuit; nargo codegen-verifier")
}

async function main() {
    await setContract(process.argv[2])

}
main()

module.exports = {
    setContract
}