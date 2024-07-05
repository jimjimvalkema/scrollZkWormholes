# example of a erc20 with EIP7503 
a erc20 token with EIP7503 (zkwormholes) style private transfers.  
Using storage proofs to track the balances of the burn addresses (bassically commitments).  


compile and proof with js (from root repo)
```shell
cd zkwormholesExample/circuits/smolProver; nargo compile; cd ../../..;  node zkwormholesExample/scripts/proof.js
```

test remint sepoilia
```shell
cd zkwormholesExample;
npx hardhat run scripts/proofAndRemint.js 
```

deploy
```shell
cd zkwormholesExample;
npx hardhat run scripts/deploy.cjs --network scrollSepolia;
npx hardhat ignition deploy ignition/modules/Token.cjs --network scrollSepolia --verify #couldnt verify within deploy.cjs so this is a hacky work around
```

sepolia scroll **block header** is **different** then scroll mainnet. It includes **baseFeePerGas**, while **mainnet scroll doesnt** yet.  
modify scripts/getScrollProof.js at getBlockHeaderRlp() for mainnet



https://sepolia.scrollscan.com/address/0xdb9fb1e8d6a0b9c0072d3e88f8330ec9cc62e21f


## generate Prover.toml and test_main() of main.nr
(just dumps it in the terminal for now)  
#### fullprover  
```shell
cd zkwormholesExample;
node scripts/getProofInputs.js --maxTreeDepth=248 --maxRlplen=850 \
--contract=0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f \
--recipient=0x93211e420c8F552a0e4836f84892a0D4eb5D6D54 \
--secret=123 \
--rpc=https://scroll-sepolia.drpc.org 
```
#### smolprover
```shell
cd zkwormholesExample;
node scripts/getProofInputs.js --maxTreeDepth=32 --maxRlplen=650 \
--contract=0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f \
--recipient=0x93211e420c8F552a0e4836f84892a0D4eb5D6D54 \
--secret=123 \
--rpc=https://scroll-sepolia.drpc.org \
```

### notes
**smolprover** is just **fullProver** but doesnt go down the full **tree depth** (maxTreeDepth) and doesnt allow for a **block header rlp** larger then **650 bytes** (maxRlplen).  
This is to **reduce ram** usage so it can be proven within **noirjs** and the browser (WASM limits to 4gb ram).  
  
The **BLOCKHASH** opcode on scroll **isnt ready** yet so the contract relies on a **trusted oracle** (the deployer) to tell the contract what blockhash is valid.

### WARNING
There is no nullifier **anyone** can double spend proofs and **drain the contract.**