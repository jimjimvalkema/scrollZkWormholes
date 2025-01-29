import { ethers } from 'ethers';
window.ethers = ethers

import circuit from '../circuits/remintProver/target/remintProver.json';
// import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { UltraHonkBackend, UltraPlonkBackend } from "@aztec/bb.js";
import { Noir } from '@noir-lang/noir_js';


import { abi as contractAbi } from "./abis/Token.json"//'../artifacts/contracts/Token.sol/Token.json'
import { getSafeRandomNumber, getProofInputs, hashNullifier, hashBurnAddress, findLatestNonce } from '../scripts/getProofInputs'
messageUi("initializing prover 🤖")
// messageUi(`<br>\ndebug SharedArrayBuffer: ${typeof SharedArrayBuffer}`, true)
complainAboutSharedBufferArray()
const backend = new UltraPlonkBackend(circuit.bytecode,{ threads: navigator.hardwareConcurrency });
const backendInitPromise = backend.instantiate().then(() => { messageUi("") })
const noir = new Noir(circuit, backend)




const CONTRACT_ADDRESS = "0x136f696481b7d48e6bcffe01a29c67080783a1ff"//"0xE182977B23296FFdBbcEeAd68dd76c3ea67f447F"
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650

const CHAININFO = {
  chainId: "0x8274f",
  rpcUrls: ["https://sepolia-rpc.scroll.io"],
  chainName: "scroll sepolia",
  nativeCurrency: {
    name: "Ethereum",
    symbol: "ETH",
    decimals: 18
  },
  blockExplorerUrls: ["https://sepolia.scrollscan.com"]
}


async function remintBtnHandler({ signerAddress, contract, secret, signer, remintAmountEl,remintAddresstEl,prevSpendAmount, burnBalance }) {
  return await dumpErrorsInUi(async () => {
    const to = remintAddresstEl.value === "" ? signerAddress : ethers.getAddress(remintAddresstEl.value)
    const amount = ethers.parseUnits(remintAmountEl.value, 18)

    const provider = contract.runner.provider
  

    const blockNumber = BigInt(await provider.getBlockNumber("latest"))
    console.log(remintAmountEl.value, prevSpendAmount)
    console.log({contract: contract.target, blockNumber, amount, to, secret, provider, MAX_HASH_PATH_SIZE, MAX_RLP_SIZE})
    const proofInputs = await getProofInputs({
      contractAddress:contract.target,
      blockNumber,
      withdrawAmount:amount, 
      remintAddress:to, 
      secret:secret, 
      provider:provider, 
      maxHashPathSize:MAX_HASH_PATH_SIZE, 
      maxRlpSize:MAX_RLP_SIZE
    })
    console.log({ proofInputs })
    messageUi("☝️🤓This is not the remint tx. This is to set the storage root \n<br> Note: setTrustedBlockHash is a workaround since scroll doesnt support the BLOCKHASH opcode yet")
    const setTrustedStorageRootTx = contract.setTrustedStorageRoot(proofInputs.proofData.stateProofData.storageRoot, proofInputs.blockData.block.number)
  
  

    const proof = createSnarkProof({ proofInputsNoirJs: proofInputs.noirJsInputs, circuit: circuit })
    putTxInUi(await setTrustedStorageRootTx)
    await proofTimeInfo()
    console.log({ proof })
    //console.log({proof})
    // TODO make this object in a new function in getProofInputs.js
    const remintInputs = {
      to,
      amount,
      blockNumber, //blockNumber: BigInt(proofInputs.blockData.block.number),
      nullifierId: proofInputs.proofData.nullifierData.nullifierId,
      nullifier: proofInputs.proofData.nullifierData.nullifier,
      snarkProof: ethers.hexlify((await proof).proof),

    }
    // console.log("------------remint tx inputs----------------")
    console.log({ remintInputs })
    // console.log("---------------------------------------")
   
    await (await setTrustedStorageRootTx).wait(1)
    await new Promise(resolve => setTimeout(resolve, 500))

    // TODO make wrapped function inside getProofInputs that consumes the remintInputs
    const remintTx = await contract.reMint(remintInputs.to, remintInputs.amount, remintInputs.blockNumber, remintInputs.nullifierId, remintInputs.nullifier, remintInputs.snarkProof)


    await putTxInUi(await remintTx)
    await remintTx.wait(1)

    //TODO this is janky af
    await refreshUiInfo({ contract, signer })
  })

}


async function dumpErrorsInUi(func, args = []) {
  try {
    return await func(...args)
  } catch (error) {
    console.error(error)
    document.querySelector("#errors").innerText += `${func.name}:${error}`
  }
}

async function switchNetwork(network, provider) {
  try {
    await provider.send("wallet_switchEthereumChain", [{ chainId: network.chainId }]);

  } catch (switchError) {
    window.switchError = switchError
    // This error code indicates that the chain has not been added to MetaMask.
    if (switchError.error && switchError.error.code === 4902) {
      try {
        await provider.send("wallet_addEthereumChain", [network]);

      } catch (addError) {
        // handle "add" error
      }
    }
    // handle other "switch" errors
  }
}

async function getContractWithSigner({ abi = contractAbi, chain = CHAININFO, contractAddress = CONTRACT_ADDRESS } = {}) {
  return await dumpErrorsInUi(
    async () => {
      const provider = new ethers.BrowserProvider(window.ethereum)
      window.provider = provider //debug moment
      await switchNetwork(chain, provider)
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(contractAddress, abi, signer)
      return { contract, signer }
    }
  )
}

async function getContractInfo(contract, signer) {
  const [userBalance, decimals, name, symbol, totalSupply] = await Promise.all([
    contract.balanceOf(signer.address),
    contract.decimals(),
    contract.name(),
    contract.symbol(),
    contract.totalSupply()
  ])
  return {
    userBalance: ethers.formatUnits(userBalance, decimals),
    totalSupply: ethers.formatUnits(totalSupply, decimals),
    decimals, name, symbol
  }
}

function setContractInfoUi({ userBalance, name, symbol }) {
  //console.log({ userBalance, name, symbol });
  [...document.querySelectorAll(".userBalance")].map((el) => el.innerText = userBalance);
  [...document.querySelectorAll(".tokenName")].map((el) => el.innerText = name);
  [...document.querySelectorAll(".ticker")].map((el) => el.innerText = symbol);
}

async function refreshUiInfo({ contract, signer }) {
  const { userBalance, totalSupply, decimals, name, symbol } = await getContractInfo(contract, signer)
  setContractInfoUi({ userBalance, name, symbol })
  await listRemintableBurnsLocalstorage({ contract, signer })
}

function messageUi(message, append = false) {
  if (append) {
    document.getElementById("messages").innerHTML += message
  } else {
    document.getElementById("messages").innerHTML = message
  }
  console.log(message)
}

async function putTxInUi(tx) {
  const explorer = CHAININFO.blockExplorerUrls[0]
  const url = `${explorer}/tx/${(await tx).hash}`
  messageUi(`tx submitted: <a href=${url}>${url}</a>`)
  return tx
}

async function mintBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("mintAmountInput").value
    const amount = ethers.parseUnits(amountUnparsed, decimals)
    const tx = await contract.mint(signer.address, amount)
    await putTxInUi(tx)
    await tx.wait(1)

    //TODO this is janky af
    await refreshUiInfo({ contract, signer })
  })
}

function addBurnToLocalStorage({ secret, burnAddress, from, txHash }) {
  burnAddress = ethers.getAddress(burnAddress) // get rid of issue where lower and uppercase addresses create duplicate entries
  secret = ethers.toBeHex(secret)
  const prevBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
  const allBurns = prevBurns !== null ? prevBurns : {}
  allBurns[burnAddress] = { secret, txHash, from }
  localStorage.setItem(CONTRACT_ADDRESS, JSON.stringify(allBurns))

}

async function listRemintableBurnsLocalstorage({ contract, signer }) {
  return await dumpErrorsInUi(async () => {
    const decimals = await contract.decimals()
    const burnedTokensUi = document.getElementById("burnedTokens")
    burnedTokensUi.innerHTML = ""
    const allBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
    if (!allBurns) return;

    for (const burnAddress in allBurns) {
      const { secret, txHash, from } = allBurns[burnAddress]
      //console.log( { secret, txHash, from } )
      //TODO do async
      const burnBalance = await contract.balanceOf(burnAddress)
      const remintUiLi = await makeRemintUi({ secret, burnBalance, burnAddress, txHash, from, contract, decimals, signer })
      burnedTokensUi.append(remintUiLi)
    }
  })
}


function br() {
  return document.createElement("br")
}


async function makeRemintUi({ secret, burnBalance, burnAddress, txHash, from, contract, decimals, signer }) {
  const explorer = CHAININFO.blockExplorerUrls[0]
  const li = document.createElement("li")

  // @optimisation cache the latest nonce and prevSpend amount so we dont need a full resync on every page load and spend
  const { prevSpendAmount } = await findLatestNonce({secret, tokenContract:contract})

  //button
  //const nullifier = hashNullifier(secret)
  // TODO show remaining balance
  //const isNullified = await contract.nullifiers(nullifier)
  console.log({ secret, burnAddress })//, nullifier,isNullified})

  const isNullified = false // TODO remove this
  if (burnBalance === prevSpendAmount) {
    li.append(
      br(),
      "all is spent",
      br(),
    )
    //li.style.textDecoration = "line-through"
  } else if (burnBalance === 0n) {
    li.append(
      br(),
      "no ballance yet. Is the the tx still pending?",
      br()
    )
    //li.style.textDecoration = "line-through"
  } else {
    const remintBtn = document.createElement("button")
    remintBtn.innerText = "remint"
    

    //remint address
    const remintAddresstEl = document.createElement("input")
    const remintAddressLabel = document.createElement("label")
    remintAddressLabel.innerText = "recipient address: "
    remintAddressLabel.append(remintAddresstEl)

    //remintAmount
    const remintAmountEl = document.createElement("input")
    const remintAmountLabel = document.createElement("label")
    remintAmountLabel.innerText = "remint amount: "
    remintAmountLabel.append(remintAmountEl)

    li.append(
      br(),
      remintAddressLabel,
      br(),
      remintAmountLabel,
      remintBtn,
      br()
    )

    // workaround for bug in circuit alway leaving 1 wei un-reminted
    remintBtn.addEventListener("click", () => remintBtnHandler({ signerAddress: signer.address, contract, secret, signer, remintAmountEl, remintAddresstEl,prevSpendAmount, burnBalance }))
  }

  //info
  const fromEl = document.createElement("a")
  const burnEl = document.createElement("a")
  fromEl.className = "address"
  burnEl.className = "address"
  fromEl.innerText = from
  burnEl.innerText = burnAddress
  fromEl.href = `${explorer}/address/${from}`
  burnEl.href = `${explorer}/address/${burnAddress}`
  li.append(
    ` burn-address: `, burnEl,
    br(),
    // `from-address: `, fromEl,
    // br(),
    `amount burned: ${ethers.formatUnits(burnBalance, decimals)},`,
    br(),
    `amount spent: ${ethers.formatUnits(prevSpendAmount, 18)}`
  )
  if (txHash) {
    const txHashEl = document.createElement("a")
    txHashEl.innerText = `${txHash}`
    txHashEl.href = `${explorer}/tx/${txHash}`
    li.append(br(), `tx: `, txHashEl)
  }
  return li
}

function complainAboutSharedBufferArray() {
  if (window.crossOriginIsolated === false) {
    messageUi(`
      \n<br>
      <b>NOTICE</b>: prover can only use <b>1 core</b> because current site isn't in a cross-origin isolation state. \n <br>
      This is likely because the server running this has not set it's cors header properly \n <br>
      They need to be set like this: \n <br>
      <code>
        ...<br>
        "Cross-Origin-Embedder-Policy":"require-corp"<br>
        "Cross-Origin-Opener-Policy":"same-origin"<br>
        ...<br>
      </code> \n<br>
      \n<br>
      <b>DEBUG</b>: \n<br>
      <code>
      SharedArrayBuffer: ${typeof SharedArrayBuffer} \n<br>
      window.crossOriginIsolated: ${window.crossOriginIsolated} \n<br>
      window.location.origin: ${window.location.origin} \n<br>
      <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements">https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements</a>
      </code>
      `, true)
  }
}

async function proofTimeInfo() {
  if (window.crossOriginIsolated === false) {
    messageUi(`
      \n<br>
      <b>NOTICE</b>: prover can only use <b>1 core</b> 
      Because current site isn't in a cross-origin isolation state. \n <br>
      Proving can take <b>7~10min</b> :/
      `
    )
  }
  await backendInitPromise
  if (window.crossOriginIsolated) {
    const b = await backend.instantiate()
    messageUi(`
      🤖 Generating zkproof 🤖 \n <br>
      DEBUG: window.crossOriginIsolated is set to true. \n<br>
      we got ${JSON.stringify(backend.backendOptions)} cores now 😎 \n <br>
      `)
  }
}

async function createSnarkProof({ proofInputsNoirJs, circuit = circuit }) {

  // pre noirjs 0.31.0 \/
  //const proof = await noir.generateProof(proofInputsNoirJs);
  const { witness } = await noir.execute(proofInputsNoirJs);
  const proof = await backend.generateProof(witness);

  //TODO remove this debug

  // pre noirjs 0.31.0 \/
  //const verified = await noir.verifyProof(proof)
  const verified = await backend.verifyProof(proof)
  console.log({ verified })

  return proof
}

async function burnBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("burnAmount").value
    console.log({ amountUnparsed })
    const amount = ethers.parseUnits(amountUnparsed, decimals)

    const secret = getSafeRandomNumber()
    const burnAddressInput = document.getElementById("burnAddressInput")
    console.log({ burnAddressInputvalue: burnAddressInput.value })
    const burnAddress = burnAddressInput.value === "" ? hashBurnAddress({secret}) : ethers.getAddress(burnAddressInput.value);
    const from = signer.address
    console.log({ secret, burnAddress, from, txHash: null })
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: null }) // user can exit page and then submit the txs so we save the secret before the burn just in case
    const burnTx = await contract.transfer(burnAddress, amount)
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: burnTx.hash }) // we got a txhash now
    await putTxInUi(burnTx)
    await burnTx.wait(1)
    await refreshUiInfo({ contract, signer })
  })

}

function setEventListeners({ contract, decimals, signer }) {
  document.getElementById("mintBtn").addEventListener("click", async () => await mintBtnHandler({ contract, decimals, signer }))
  document.getElementById("burnBtn").addEventListener("click", async () => await burnBtnHandler({ contract, decimals, signer }))
}

async function main() {
  const { contract, signer } = await getContractWithSigner()
  const { userBalance, totalSupply, decimals, name, symbol } = await getContractInfo(contract, signer)
  setContractInfoUi({ userBalance, name, symbol })
  setEventListeners({ contract, decimals, signer })
  await listRemintableBurnsLocalstorage({ contract, signer })



  //--------------------------
  window.contract = contract
  window.signer = signer

  const walletLatestBlock = ethers.toBigInt((await provider.getBlock("latest")).number)
  const etherscanLatestBlock = ethers.toBigInt((await (await fetch(`https://api-sepolia.scrollscan.com/api?module=proxy&action=eth_blockNumber&apikey=YGETYAVVAW8V4JY9T92C3BFMFHG53HRPMH`)).json()).result)
  const nBlockWalletBehindEtherscan = etherscanLatestBlock - walletLatestBlock
  console.log({walletLatestBlock, etherscanLatestBlock, nBlockWalletBehindEtherscan})
}

await main()