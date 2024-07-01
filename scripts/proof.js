import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import {getProofData, getProofInputsObj} from "./getProofInputs.js"

import circuit from '../circuit/target/zkwormholesEIP7503.json'  assert {type: 'json'};


const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend)
const {block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider, burnAddress}  = await getProofData()
const input =  await getProofInputsObj(block, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths, provider)
console.log(input)

const proof = await noir.generateProof(input);
console.log(proof)
// idk its not stopping on its own prob wasm thing?
process.exit();