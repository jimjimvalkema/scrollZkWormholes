# example of a erc20 with EIP7503 
a erc20 token with EIP7503 (zkwormholes) style private transfers.  
Using storage proofs to track the balances of the burn addresses (bassically commitments).  



```shell
npx hardhat help
npx hardhat test
REPORT_GAS=true npx hardhat test
npx hardhat node
npx hardhat ignition deploy ./ignition/modules/Lock.js
```
