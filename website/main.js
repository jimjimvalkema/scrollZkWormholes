import { ethers } from 'ethers';
window.ethers = ethers

import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json';
import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';


import {abi as  contractAbi} from '../artifacts/contracts/Token.sol/Token.json'
import {getSafeRandomNumber} from '../scripts/getProofInputs'
const CONTRACT_ADDRESS = "0x0C506a4855Ab156DB9A504AE5C2c9a50f2FF9BA2"
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const SEPOLIA = {
    chainId: "0xaa36a7",
    rpcUrls: ["https://rpc.sepolia.org/"],
    chainName: "sepolia",
    nativeCurrency: {
      name: "Ethereum",
      symbol: "ETH",
      decimals: 18
    },
    blockExplorerUrls: ["https://sepolia.etherscan.io/"]
}

const contract = await getContractWithSigner()

async function getContractWithSigner({abi=contractAbi, chain=SEPOLIA, contractAddress=CONTRACT_ADDRESS}={}) {
  return await dumpErrorsInUi(
    async ()=>{
      const provider = new ethers.BrowserProvider(window.ethereum)
      await switchNetwork(chain, provider)
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(contractAddress, abi, signer)
      return contract
    }
  )

}

async function switchNetwork(network,provider) {
  try {
      await provider.send("wallet_switchEthereumChain",[{ chainId: network.chainId }]);

    } catch (switchError) {
      window.switchError = switchError
      // This error code indicates that the chain has not been added to MetaMask.
      if (switchError.error && switchError.error.code === 4902) {
        try {
          await provider.send("wallet_addEthereumChain",[network]);

        } catch (addError) {
          // handle "add" error
        }
      }
      // handle other "switch" errors
    }
}

async function dumpErrorsInUi(func, args=[]) {
  try {
      await func(...args)
  } catch (error) {
      console.error(error)
      document.querySelector("#errors").innerText += `${func.name}:${error}`    
  } 
}