// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
// no dencun
// https://docs.scroll.io/en/developers/developer-quickstart/#configure-your-tooling
pragma solidity 0.8.23;

//import "../../circuits/zkwormholesEIP7503/contract/zkwormholesEIP7503/plonk_vk.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}

error VerificationFailed();

contract Token is ERC20, Ownable, ERC20Permit {
    mapping(bytes32 => bool) public nullifiers;
    // smolverifier doesnt go down the full 248 depth of the tree but is able to run witn noir js (and is faster)
    address public smolVerifier;
    address public fullVerifier;

    // @workaround since BLOCKHASH opcode is useless
    // https://docs.scroll.io/en/technology/chain/differences/#opcodes
    mapping (uint256 => bytes32) public trustedBlockhash;
    //function setBlockHash(bytes32 blockHash, uint256 blockNum) public onlyOwner {
    function setBlockHash(bytes32 blockHash, uint256 blockNum) public {
        trustedBlockhash[blockNum] = blockHash;
    }

    constructor()
        ERC20("zkwormholes-token", "WRMHL")
        Ownable(msg.sender)
        ERC20Permit("token")
    {
    }

    function setVerifiers(address _fullVerifier, address _smolVerifier) public onlyOwner {
        require(smolVerifier == address(0x0000000000000000000000000000000000000000), "verifier is already set silly");
        require(fullVerifier == address(0x0000000000000000000000000000000000000000), "verifier is already set silly");
        fullVerifier = _fullVerifier;
        smolVerifier = _smolVerifier;
    }

    // //---------------debug--------------------------
    // // TODO remove debug
    // function reMintTest(address to, uint256 amount, uint256 blockNum, bytes calldata snarkProof, bytes32[] calldata publicInputs) public {
    //     if (!IVerifier(smolVerifier).verify(snarkProof, publicInputs)) {
    //         revert VerificationFailed();
    //     }
    //     _mint(to, amount);
    // }

    // // TODO remove debug
    // function getBlockHash(uint256 blocknum) public view returns(bytes32){
    //     return blockhash(blocknum);
    // }

    // // TODO remove debug
    // function computeFakeBlockHash(uint256 blocknum) public view returns(bytes32){
    //     return keccak256(abi.encode(block.chainid, blocknum));
    // }

    // // TODO remove debug // WARNING anyone can mint
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    //---------------public---------------------
    function reMint(address to, uint256 amount, uint256 blockNum, bytes32 nullifier, bytes calldata snarkProof) public {
        _reMint( to,  amount,  blockNum, nullifier, snarkProof,  smolVerifier);
    }

    // just incase the contracts leaf will sit deeper than 53
    // or less likely the storage tree becomes deeper than 53
    function reMintFullVerifier(address to, uint256 amount, uint256 blockNum, bytes32 nullifier, bytes calldata snarkProof) public {
        _reMint( to,  amount,  blockNum, nullifier, snarkProof,  fullVerifier);
    }

    // verifier wants the [u8;32] (bytes32 array) as bytes32[32] array.
    // ex: bytes32[32] array = ['0x0000000000000000000000000000000000000000000000000000000000000031','0x0000000000000000000000000000000000000000000000000000000000000027',etc]
    // but fields can be normal bytes32
    // all public inputs are put into a flattened array
    // so in our case array = [Field + bytes32, bytes32 + Field]. which the lenght will be: 1 + 32 + 32 = 66
    //TODO make private
    // TODO see much gas this cost and if publicInputs can be calldata
    // does bit shifting instead of indexing save gas?
    function _formatPublicInputs(address to, uint256 amount, bytes32 blkhash, bytes32 nullifier) public pure returns (bytes32[] memory) {
        bytes32 amountBytes = bytes32(uint256(amount));
        bytes32 toBytes = bytes32(uint256(uint160(bytes20(to))));
        bytes32[] memory publicInputs = new bytes32[](66);
        publicInputs[0] = toBytes;
        for (uint i=1; i < 33; i++) {
            publicInputs[i] = bytes32(uint256(uint8(amountBytes[i-1])));
        }
        for (uint i=33; i < 65; i++) {
            publicInputs[i] = bytes32(uint256(uint8(blkhash[i-33])));
        }
        publicInputs[65] = nullifier;
        return publicInputs;
    }

    function _reMint(address to, uint256 amount, uint256 blockNum, bytes32 nullifier, bytes calldata snarkProof, address _verifier) private {
        require(nullifiers[nullifier] == false, "burn address already used");
        nullifiers[nullifier] = true;

        // @workaround
        //blockhash() is fucking use less :,(
        //bytes32 blkhash = blockhash(blockNum);
        bytes32 blkhash = trustedBlockhash[blockNum];
        bytes32[] memory publicInputs = _formatPublicInputs(to, amount, blkhash, nullifier);
        if (!IVerifier(_verifier).verify(snarkProof, publicInputs)) {
            revert VerificationFailed();
        }
        //TODO suppy shouldnt increase here (because it doesn't!)
        _mint(to, amount);
    }
}
