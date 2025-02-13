// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
// no dencun
// https://docs.scroll.io/en/developers/developer-quickstart/#configure-your-tooling
pragma solidity ^0.8.23;

//import "../../circuits/zkwormholesEIP7503/contract/zkwormholesEIP7503/plonk_vk.sol";
import {ERC20} from "./ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}

error VerificationFailed();
event Remint(bytes32 indexed nullifierKey, uint256 amount);
event StorageRootAdded(uint256 blockNumber);

contract Token is ERC20, Ownable {
    // @notice nullifierKey = poseidon(nonce, secret)
    // @notice nullifierValue = poseidon(amountSpent, nonce, secret)
    mapping (bytes32 => bytes32) public partialNullifiers; // nullifierKey -> nullifierValue 
    mapping (bytes32 => uint256) public reMintAmounts; 

    // remintVerifier doesnt go down the full 248 depth (32 instead) of the tree but is able to run witn noir js (and is faster)
    address public remintVerifier;
    address public storageRootVerifier;

    mapping (uint256 => bytes32) public storageRoots;

    // @NOTICE useless since scrolls BLOCKHASH opcode is broken
    function setStorageRoot(bytes32 storageRoot, uint256 blockNum, bytes calldata snarkProof) public {
        // scroll returns a blockhash without the storage root
        bytes32 blockHash = blockhash(blockNum);
        
        bytes32[] memory publicInputs = _formatPublicStorageRootInputs(storageRoot, blockHash, address(this));
        if (!IVerifier(storageRootVerifier).verify(snarkProof, publicInputs)) {
            revert VerificationFailed();
        }
        storageRoots[blockNum] = storageRoot;

        emit StorageRootAdded(blockNum);
    }

    // @TODO @WARNING contract insecure because of this workaround because blockhash opcode is not supported
    // https://docs.scroll.io/en/technology/chain/differences/#opcodes
    function setTrustedStorageRoot(bytes32 storageRoot, uint256 blockNum) public {// onlyOwner() {
        storageRoots[blockNum] = storageRoot;
    }


    // TODO makes this weth like instead of its own token
    constructor()
        ERC20("zkwormholes-token", "WRMHL")
        Ownable(msg.sender)
    {
    }

    function setVerifiers(address _storageRootVerifier, address _remintVerifier) public onlyOwner {
        require(remintVerifier == address(0x0000000000000000000000000000000000000000), "verifier is already set silly");
        require(storageRootVerifier == address(0x0000000000000000000000000000000000000000), "verifier is already set silly");
        storageRootVerifier = _storageRootVerifier;
        remintVerifier = _remintVerifier;
    }

    // // TODO remove debug // WARNING anyone can mint
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    //---------------public---------------------
    function reMint(address to, uint256 amount, uint256 blockNum, bytes32 nullifierKey, bytes32 nullifierValue, bytes calldata snarkProof) public {
        _reMint( to,  amount,  blockNum, nullifierKey, nullifierValue, snarkProof,  remintVerifier);
    }

    // verifier wants the [u8;32] (bytes32 array) as bytes32[32] array.
    // ex: bytes32[32] array = ['0x0000000000000000000000000000000000000000000000000000000000000031','0x0000000000000000000000000000000000000000000000000000000000000027',etc]
    // but fields can be normal bytes32
    // all public inputs are put into a flattened array
    // so in our case array = [Field + bytes32, bytes32 + Field]. which the lenght will be: 1 + 32 + 32 = 66
    //TODO make private
    // TODO see much gas this cost and if publicInputs can be calldata
    // does bit shifting instead of indexing save gas?
    function _formatPublicRemintInputs(address to, uint256 amount, bytes32 storageRoot, bytes32 nullifierKey, bytes32 nullifierValue) public pure returns (bytes32[] memory) {
        bytes32 amountBytes = bytes32(uint256(amount));
        bytes32 toBytes = bytes32(uint256(uint160(bytes20(to))));
        bytes32[] memory publicInputs = new bytes32[](5);

        publicInputs[0] = toBytes;
        publicInputs[1] = amountBytes;
        publicInputs[2] = nullifierValue;
        publicInputs[3] = nullifierKey;
        publicInputs[4] = storageRoot;

        return publicInputs;
    }

    function _formatPublicStorageRootInputs(bytes32 storageRoot, bytes32 blockHash, address contractAddress) public pure returns(bytes32[] memory) {
        bytes32[] memory publicInputs = new bytes32[](65);
        publicInputs[0] = storageRoot;
        bytes20 contractAddressBytes = bytes20(contractAddress);

        for (uint i=1; i < 33; i++) {
            publicInputs[i] = bytes32(uint256(uint8(blockHash[i-1])));
        }

        // only copy first 20 bytes, rest can stay zero
        for (uint i=33; i < 53; i++) {
            publicInputs[i] = bytes32(uint256(uint8(contractAddressBytes[i-33])));
        }
        return publicInputs;
    }

    function _reMint(address to, uint256 amount, uint256 blockNum, bytes32 nullifierKey, bytes32 nullifierValue, bytes calldata snarkProof, address _verifier) private {
        //require(nullifiers[nullifier] == false, "burn address already used");
        require(partialNullifiers[nullifierKey] == bytes32(0x0), "nullifier already exist");
        partialNullifiers[nullifierKey] = nullifierValue;

        // @workaround
        //blockhash() is fucking use less :,(
        //bytes32 blkhash = blockhash(blockNum);
        bytes32 storageRoot = storageRoots[blockNum];
        bytes32[] memory publicInputs = _formatPublicRemintInputs(to, amount, storageRoot, nullifierKey, nullifierValue);
        if (!IVerifier(_verifier).verify(snarkProof, publicInputs)) {
            revert VerificationFailed();
        }
        unchecked {
            // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.
            _balances[to] += amount;
        }
        emit Transfer(address(0), to, amount);
        emit Remint(nullifierKey, amount);
        reMintAmounts[nullifierKey] = amount; // we can do without this to save gas but i am too lazy for event scanning 
    }
}