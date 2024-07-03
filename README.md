# example of a erc20 with EIP7503 
a erc20 token with EIP7503 (zkwormholes) style private transfers.  
Using storage proofs to track the balances of the burn addresses (bassically commitments).  


compile and proof with js (from root repo)
```shell
cd zkwormholesExample/circuits/smolProver; nargo compile; cd ../../..;  node zkwormholesExample/scripts/proof.js
```
populate prover.tom (terminal out put prints test for main.nr)
```shell
bun run zkwormholesExample/scripts/getProofInputs.js format
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

sepolia scroll block header is differen and baseFeePerGas
modify scripts/getScrollProof.js at getBlockHeaderRlp() for mainnet

```shell
npx hardhat help
npx hardhat test
REPORT_GAS=true npx hardhat test
npx hardhat node
npx hardhat ignition deploy ./ignition/modules/Lock.js
```
