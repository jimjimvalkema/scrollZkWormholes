import { ethers } from 'ethers';
window.ethers = ethers

import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json';
import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';


import { abi as contractAbi } from '../artifacts/contracts/Token.sol/Token.json'
import { getSafeRandomNumber , getProofInputs} from '../scripts/getProofInputs'
const CONTRACT_ADDRESS = "0xB10f8e42cBF1b2075d0447Cd40213c046DEB9940"
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const CHAININFO = {
  chainId: "0x8274f",
  rpcUrls: ["https://sepolia-rpc.scroll.io/"],
  chainName: "scroll sepolia",
  nativeCurrency: {
    name: "Ethereum",
    symbol: "ETH",
    decimals: 18
  },
  blockExplorerUrls: ["https://api-sepolia.scrollscan.com"]
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
  document.querySelectorAll(".userBalance").innerText = userBalance
  document.querySelectorAll(".tokenName").innerText = name
  document.querySelectorAll(".ticker").innerText = symbol
}

async function refreshUiInfo({ contract,signer }) {
  const { userBalance, totalSupply, decimals, name, symbol } = await getContractInfo(contract, signer)
  setContractInfoUi({ userBalance, name, symbol })
  await listRemintableBurnsLocalstorage({ contract, signer})
}

function messageUi(message) {
  document.getElementById("messages").innerText = message
  console.log(message)
}

async function putTxInUi(tx) {
  const explorer = CHAININFO.blockExplorerUrls[0]
  messageUi(`tx submitted: ${explorer}/${tx.hash}`)
  messageUi(`tx confirmed: ${explorer}/${(await tx.wait(1)).hash}`)
}

async function mintBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("mintAmountInput").value
    const amount = ethers.parseUnits(amountUnparsed, decimals)
    const tx = await contract.mint(signer.address, amount)
    await putTxInUi(tx)

    //TODO this is janky af
    await refreshUiInfo({ contract,signer })
  })
}

function addBurnToLocalStorage({ secret, burnAddress, from, txHash }) {
  secret = ethers.toBeHex(secret)
  const prevBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
  let allBurns = {}
  if (prevBurns !== null) allBurns = prevBurns
  allBurns[burnAddress] = { secret, txHash, from }
  localStorage.setItem(CONTRACT_ADDRESS, JSON.stringify(allBurns))
}

async function listRemintableBurnsLocalstorage({ contract,signer }) {
  return await dumpErrorsInUi(async () => {
    const decimals = await contract.decimals()
    const burnedTokensUi = document.getElementById("burnedTokens")
    burnedTokensUi.innerHTML = ""
    const allBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
    if (!allBurns) return;
    
    for (const burnAddress in allBurns) {
      const { secret, txHash, from } = allBurns[burnAddress]
      console.log( { secret, txHash, from } )
      //TODO do async
      const burnBalance = await contract.balanceOf(burnAddress)
      if (txHash || burnBalance > 0n) { // no tx? no balance? nothing there!
        const remintUiLi = await makeRemintUi({secret, burnBalance, burnAddress, txHash, from, contract,decimals,signer })
        burnedTokensUi.append(remintUiLi)
      }
    }
  })
}


function br() {
  return document.createElement("br")
}

function hashNullifier(secret, remintAddress) {
  return ethers.zeroPadValue(ethers.toBeHex(poseidon2([secret, ethers.toBigInt(remintAddress)])),32)
}

async function makeRemintUi({ secret,burnBalance, burnAddress, txHash, from, contract,decimals ,signer}) {
  const explorer = CHAININFO.blockExplorerUrls[0]

  //info
  const li = document.createElement("li")
  const fromEl = document.createElement("a")
  const burnEl = document.createElement("a")
  fromEl.className = "address"
  burnEl.className = "address"
  fromEl.innerText = from
  burnEl.innerText = burnAddress
  fromEl.href = `${explorer}/address/${from}`
  burnEl.href = `${explorer}/address/${burnAddress}`
  li.append(
    `from-address: `,fromEl,
    br(),
    ` burn-address: `,burnEl,
    br(),
    `amount: ${ethers.formatUnits(burnBalance, decimals)},`,
  )
  if (txHash) {
    const txHashEl = document.createElement("a")
    txHashEl.innerText = `${txHash}`
    txHashEl.href = `${explorer}/${txHash}`
    li.append(br(), `tx: `,txHashEl)
  }

  //button
  const nullifier = hashNullifier(secret, burnBalance)
  console.log({nullifier})
  const isNullified = await contract.nullifiers(nullifier)
  if (isNullified) {
    li.append(
      br(),
      "already reminted"
    )
    li.style.textDecoration = "line-through"
  } else {
    const remintBtn = document.createElement("button")
    remintBtn.innerText = "remint"
    li.append(
      br(),
      remintBtn
    )
    remintBtn.addEventListener("click", ()=>remintBtnHandler({ to:signer.address, contract, secret,signer }))
  }
  return li
}

async function creatSnarkProof({ proofInputsNoirJs, circuit = circuit }) {
  messageUi("NOTICE: noirjs can only use 1 core. This can take up to 7min :/")
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

async function remintBtnHandler({ to, contract, secret , signer}) {
  const provider = contract.runner.provider
  const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
  const MAX_RLP_SIZE = 650

  const blockNumber = BigInt(await provider.getBlockNumber("latest"))
  const proofInputs = await getProofInputs(contract.target, blockNumber, to, secret, provider, MAX_HASH_PATH_SIZE, MAX_RLP_SIZE)
  const amount = proofInputs.proofData.burnedTokenBalance

  const proof = await creatSnarkProof({ proofInputsNoirJs: proofInputs.noirJsInputs, circuit: circuit })
  console.log({proof})
  
  const remintInputs = {
    to,
    amount,
    blockNumber, //blockNumber: BigInt(proofInputs.blockData.block.number),
    nullifier: ethers.toBeHex(proofInputs.proofData.nullifier),
    snarkProof: ethers.hexlify(proof.proof),

  }
  console.log("------------remint tx inputs----------------")
  console.log({ remintInputs })
  console.log("---------------------------------------")

  const setBlockHashTx = contract.setBlockHash(proofInputs.blockData.block.hash,remintInputs.blockNumber)
  const remintTx = contract.reMint(remintInputs.to, remintInputs.amount, remintInputs.blockNumber, remintInputs.nullifier, remintInputs.snarkProof)

  await putTxInUi(await setBlockHashTx)
  await putTxInUi(await remintTx)

  //TODO this is janky af
  await refreshUiInfo({ contract,signer})

}

async function burnBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("burnAmount").value
    const amount = ethers.parseUnits(amountUnparsed, decimals)

    const secret = getSafeRandomNumber()
    const burnAddress = ethers.toBeHex(poseidon1([secret])).slice(0, 2 + 40) // take only first 20 bytes (because eth address are 20 bytes)
    const from = signer.address
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: null }) // user can exit page and then submit the txs so we save it before the burn just in case
    const burnTx = await contract.transfer(burnAddress, amount)
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: burnTx.hash }) // we got a txhash now
    await putTxInUi(burnTx)
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
  await listRemintableBurnsLocalstorage({contract, signer})



  //--------------------------
  window.contract = contract
  window.signer = signer
  console.log(contract)

}

await main()