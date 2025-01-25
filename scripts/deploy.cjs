
// const hre = require("hardhat");

const verifiersModule = require("../ignition/modules/Verifiers.cjs");
const tokenModule = require("../ignition/modules/Token.cjs")
// const {setContractCircuit} = require("./setContractAddresCircuit.cjs")
const {generateSolidityVerifier} = require("./generateSolidityVerifier.cjs")
// const Verifiers = require("../ignition/modules/Verifiers.cjs");

const REMINTPROVER_CIRCUIT_ROOT = __dirname+"/../circuits/remintProver/"
const REMINTPROVER_CIRCUIT_NAME = "remintProver"
const REMINTPROVER_VERIFIER_NAME = "RemintVerifier"

const STORAGEROOT_CIRCUIT_ROOT = __dirname+"/../circuits/storageRootProver/"
const STORAGEROOT_CIRCUIT_NAME = "storageRootProver"
const STORAGEROOT_VERIFIER_NAME = "StorageRootVerifier"


const CONTRACTS_ROOT = __dirname + "/../contracts"


//TODO use hardhat vars
const PROVIDERURL = "https://sepolia-rpc.scroll.io/"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)

async function main() {
  const { token } = await hre.ignition.deploy(tokenModule,)
  const tokenAddress = await token.getAddress()
  await token.waitForDeployment()
  await new Promise(resolve => setTimeout(resolve, 60000));//1 min // we rely on eth_getProof to set constants of circuit.
  // console.log(`generating verifier contracts code with new token address: ${tokenAddress}`)
  const generatedSolidityVerifiers = await Promise.all([
    generateSolidityVerifier(REMINTPROVER_CIRCUIT_ROOT, REMINTPROVER_CIRCUIT_NAME, REMINTPROVER_VERIFIER_NAME, CONTRACTS_ROOT),
    generateSolidityVerifier(STORAGEROOT_CIRCUIT_ROOT, STORAGEROOT_CIRCUIT_NAME ,STORAGEROOT_VERIFIER_NAME, CONTRACTS_ROOT)
    // setContractCircuit(tokenAddress, FULLPROVER_MAIN, FULLPROVER_SOLIDITY_VERIFIER_DESTINATION, "RemintVerifier", provider), 
    // setContractCircuit(tokenAddress, SMOLPROVER_MAIN, SMOLPROVER_SOLIDITY_VERIFIER_DESTINATION, "StoragerootVerifier", provider)
  ])
  console.log(`succesfully generated verifiers: ${JSON.stringify(generatedSolidityVerifiers)}`)
  await new Promise(resolve => setTimeout(resolve, 10000));

  //compile and depoly
  await hre.run("compile") // hre.ignition.deploy doesnt recompile inside hardhat run,  recompile happens when "npx hardhat run script/deploy.cjs" is run. so contracts modified in here dont get recompilled i have spend days trying to fix a bug created by this issue :(
    const {  RemintVerifier, StorageRootVerifier } = await hre.ignition.deploy(verifiersModule,{
    parameters: { VerifiersModule: {tokenAddress}  },
  });
  await RemintVerifier.waitForDeployment()
  await StorageRootVerifier.waitForDeployment()
  console.log(`
    token deployed to: ${tokenAddress}
    with verifiers to: 
      ${REMINTPROVER_VERIFIER_NAME}:${await RemintVerifier.getAddress()}, 
      ${STORAGEROOT_VERIFIER_NAME}: ${await StorageRootVerifier.getAddress()})}
  `);

  // TODO keep the compiled circuit somewhere safe where we can track wich address there deployed to
  //await new Promise(resolve => setTimeout(resolve, 60000));//1 min 
  // const contracts = {
  //   token: tokenAddress,
  //   fullVerifier: await FullVerifier.getAddress(),
  //   smollVerifier: await SmolVerifier.getAddress()
  // }

  // //verify (source: https://hardhat.org/hardhat-runner/plugins/nomiclabs-hardhat-etherscan#using-programmatically)
  // // sequential  because might get rate limited
  // // TODO this fails to verify
  // for (const [name, address] of Object.entries(contracts)) {
  //   console.log(`verifing: ${name}: ${address}`)
  //   await hre.run("verify:verify", {
  //     address: address,
  //     constructorArguments: [],
  //   });
  //   await new Promise(resolve => setTimeout(resolve, 10000));//10 seconds 
    
  // }
  // console.log(`verifing: token: ${tokenAddress}`)
  // await hre.run("verify:verify", {
  //   address: tokenAddress,
  //   //constructorArguments: [],
  //   contract: "contracts/Token.sol:Token"
  // });
  // console.log(`verifing: FullVerifier: ${await FullVerifier.getAddress()}`)
  // await hre.run("verify:verify", {
  //   address: await FullVerifier.getAddress(),
  //   //constructorArguments: [],
  //   contract: "contracts/FullVerifier.sol:FullVerifier"
  // });
  // console.log(`verifing: SmolVerifier: ${await SmolVerifier.getAddress()}`)
  // await hre.run("verify:verify", {
  //   address: await SmolVerifier.getAddress(),
  //   //constructorArguments: [],
  //   contract: "contracts/SmolVerifier.sol:SmolVerifier"
  // });

  // console.log(`
  //   token deployed to: ${tokenAddress}
  //   with verifiers to: 
  //     FullVerifier:${await FullVerifier.getAddress()}, 
  //     SmolVerifier: ${await SmolVerifier.getAddress()})}
  // `);


}

main().catch(console.error);