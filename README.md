# An erc20 with EIP7503, partial spends and reusable address
An erc20 token with [EIP7503](https://eips.ethereum.org/EIPS/eip-7503) (zkwormholes) style private transfers, and a new nullifier scheme to enable partial spends and reusable burnaddresses.  
*More info in [docs/notes.md](https://github.com/jimjimvalkema/scrollZkWormholes/blob/main/docs/notes.md#L1)*

**Try it out here: https://scrollzkwormholes.jimjim.dev/**  
<!-- TODO -> *Or on ipfs: https://bafybeia3aeuhou4jwtoakvds7ya5qxe5hwjqchmabvvvuwvd6thnqubgzm.ipfs.dweb.link/* -->


![ui](./screenshots/2burns1remintui.png)  

### deploymend on scroll sepolia
https://sepolia.scrollscan.com/address/0x136F696481b7d48e6BcffE01a29c67080783A1ff

## WARNING WORK IN PROGRESS
The code here in barely tested and has 3 bugs that are inflation bugs.  
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
```shell
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash;
source ~/.bashrc;
noirup -v 0.32.0;
source ~/.bashrc;
```
barretenberg
```shell
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash;
source ~/.bashrc;
bbup -nv 0.32.0;
source ~/.bashrc;
sudo apt install libc++-dev;
```

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
yarn hardhat ignition deploy ignition/modules/Token.cjs --network scrollSepolia --verify 
```


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