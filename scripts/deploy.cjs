
// const hre = require("hardhat");

const verifiersModule = require("../ignition/modules/Verifiers.cjs");
const tokenModule = require("../ignition/modules/Token.cjs")
const {setContractCircuit} = require("./setContractAddresCircuit.cjs")
// const Verifiers = require("../ignition/modules/Verifiers.cjs");

const FULLPROVER_MAIN = __dirname+"/../circuits/fullProver/src/main.nr"
const FULLPROVER_SOLIDITY_VERIFIER_DESTINATION = __dirname+"/../contracts/FullVerifier.sol"

const SMOLPROVER_MAIN = __dirname+"/../circuits/smolProver/src/main.nr"
const SMOLPROVER_SOLIDITY_VERIFIER_DESTINATION = __dirname+"/../contracts/SmolVerifier.sol"


//TODO vars
const PROVIDERURL = "https://scroll-sepolia.drpc.org"
const provider = new ethers.JsonRpcProvider(PROVIDERURL)

async function main() {
  const { token } = await hre.ignition.deploy(tokenModule,)
  const tokenAddress = await token.getAddress()
  await token.waitForDeployment()
  await new Promise(resolve => setTimeout(resolve, 60000));//1 min // we rely on eth_getProof to set constants of circuit.
  console.log(`generating verifier contracts code with new token address: ${tokenAddress}`)
  const generatedSolidityVerifiers = await Promise.all([
    setContractCircuit(tokenAddress, FULLPROVER_MAIN, FULLPROVER_SOLIDITY_VERIFIER_DESTINATION, "FullVerifier", provider), 
    setContractCircuit(tokenAddress, SMOLPROVER_MAIN, SMOLPROVER_SOLIDITY_VERIFIER_DESTINATION, "SmolVerifier", provider)
  ])
  console.log(`succesfully generated verifiers: ${JSON.stringify(generatedSolidityVerifiers)}`)
  await new Promise(resolve => setTimeout(resolve, 10000));
  await hre.run("compile") // hre.ignition.deploy doesnt recompile inside hardhat run,  recompile happens when "npx hardhat run script/deploy.cjs" is run. so contracts modified in here dont get recompilled i have spend days trying to fix a bug created by this issue :(
  const { FullVerifier, SmolVerifier } = await hre.ignition.deploy(verifiersModule,{
    parameters: { VerifiersModule: {tokenAddress}  },
  });
  await FullVerifier.waitForDeployment()
  await SmolVerifier.waitForDeployment()
  console.log(`
    token deployed to: ${tokenAddress}
    with verifiers to: 
      FullVerifier:${await FullVerifier.getAddress()}, 
      SmolVerifier: ${await SmolVerifier.getAddress()})}
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