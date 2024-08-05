# example of a erc20 with EIP7503 
An erc20 token with [EIP7503](https://eips.ethereum.org/EIPS/eip-7503) (zkwormholes) style private transfers.  
Using storage proofs to track the balances of the burn addresses (bassically commitments). 

### deploymed on scroll sepolia
https://sepolia.scrollscan.com/address/0x038a89A0f0882506DEd867FB46702106276dBb90

## install
```shell
yarn install
```

## deploy
### set environment variables
```shell
npx hardhat vars set PRIVATE_KEY; #<=deployment key
npx hardhat vars set SEPOLIA_SCROLL_ETHERSCAN_KEY;;
```



### deploy
```shell
cd zkwormholesExample;
npx hardhat run scripts/deploy.cjs --network scrollSepolia;
npx hardhat ignition deploy ignition/modules/Token.cjs --network scrollSepolia --verify #couldnt verify within deploy.cjs so this is a hacky work around
```


## test remint sepoilia
### set reminter privatekey (can be same as deployer)
```shell
npx hardhat vars set RECIPIENT_PRIVATE_KEY;
```


### do remint
```shell
cd zkwormholesExample;
npx hardhat run scripts/proofAndRemint.js 
```

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

## notes
**smolprover** is just **fullProver** but doesnt go down the full **tree depth** (maxTreeDepth) and doesnt allow for a **block header rlp** larger then **650 bytes** (maxRlplen).  
This is to **reduce ram** usage so it can be proven within **noirjs** and the browser (WASM limits to 4gb ram).  
  
The **BLOCKHASH** opcode on scroll **isnt ready** yet so the contract relies on a **trusted oracle** (the deployer) to tell the contract what blockhash is valid.  
  
sepolia scroll **block header** is **different** then scroll mainnet. It includes **baseFeePerGas**, while **mainnet scroll doesnt** yet.  
modify **scripts/getScrollProof.js** at getBlockHeaderRlp() for mainnet

### WARNING
There is no nullifier **anyone** can double spend proofs and **drain the contract.**