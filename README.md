# An erc20 with EIP7503, partial spends and reusable address
An erc20 token with [EIP7503](https://eips.ethereum.org/EIPS/eip-7503) (zkwormholes) style private transfers, and a new nullifier scheme to enable partial spends and reusable burnaddresses.  
*More info in [docs/notes.md](https://github.com/jimjimvalkema/scrollZkWormholes/blob/main/docs/notes.md#L1)*

**Try it out here: https://scrollzkwormholes.jimjim.dev/**  
<!-- TODO -> *Or on ipfs: https://bafybeia3aeuhou4jwtoakvds7ya5qxe5hwjqchmabvvvuwvd6thnqubgzm.ipfs.dweb.link/* -->


![ui](./screenshots/2burns1remintui.png)  

### deploymend on scroll sepolia
https://sepolia.scrollscan.com/address/0x6A0e54612253d97Fd2c3dbb73BDdBAFfca531A9B

## WARNING WORK IN PROGRESS
The code here in barely tested and has 3 inflation bugs.  
These are: anyone can call `setTrustedStorageRoot` and `mint`.  
Also EOA<->zkwormhole address collisions can be created.  
*More info in [docs/notes.md](https://github.com/jimjimvalkema/scrollZkWormholes/blob/main/docs/notes.md#L8)*


## install
### js
```shell
yarn install;
yarn install-submodules && yarn install-vite;
```
### Install noir
nargo  
https://noir-lang.org/docs/getting_started/quick_start#noir
```shell
noirup -v 1.0.0-beta.1;
```
barretenberg  
https://noir-lang.org/docs/getting_started/quick_start#proving-backend  
```shell
bbup -v 0.66.0
```
<!-- ```shell
bbup -v 1.0.0-beta.1;
``` -->

## Run ui locally
```shell
yarn dev
```

## Build static site locally
```shell
yarn build
```

## Deploy
### Set environment variables
```shell
yarn hardhat vars set PRIVATE_KEY; #<=deployment key
yarn hardhat vars set SEPOLIA_SCROLL_ETHERSCAN_KEY;
yarn compile-contracts;
```

### Deploy contracts
<!-- TODO dont do recompile circuits in scripts/deploy.cjs  -->
```shell
rm -fr ignition/deployments;
yarn hardhat run scripts/deploy.cjs --network scrollSepolia;
cp artifacts/contracts/Token.sol/Token.json website/abis/Token.json;
yarn hardhat ignition deploy ignition/modules/Token.cjs --network scrollSepolia --verify 
```
you need to manually change the contract address:  
ui: [website/main.js](https://github.com/jimjimvalkema/scrollZkWormholes/blob/main/) at line 22     
ui: [scripts/proofAndRemint.js](https://github.com/jimjimvalkema/scrollZkWormholes/blob/main/scripts/proofAndRemint.js#L213) at line 213    


## Test
### set reminter privatekey 
(can be same as deployer)
```shell
yarn hardhat vars set RECIPIENT_PRIVATE_KEY;
```  
  
### do remint
```shell
yarn hardhat run scripts/proofAndRemint.js 
```


### test circuit
```shell
cd circuits/remintProver;
nargo test;
```
```shell
cd circuits/storageRootProver;
nargo test;
```

### Compile circuit (verifier contracts are created in `scripts/deploy.cjs`)
```shell
yarn compile-circuits 
```
### get storage slots layout
```shell
forge inspect contracts/Token.sol:Token storage --pretty > contracts/storagelayouts/Token.txt
```