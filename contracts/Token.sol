// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
// no dencun
// https://docs.scroll.io/en/developers/developer-quickstart/#configure-your-tooling
pragma solidity ^0.8.23;

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
    address public verifier;

    constructor(address _verifier)
        ERC20("token", "tkn")
        Ownable(msg.sender)
        ERC20Permit("token")
    {
        verifier = _verifier;
    }

    // WARNING anyone can mint
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function reMint(address to, uint256 amount, uint256 blockNum, bytes calldata snarkProof) public {
        //TODO nullifier WARNING anyone can double spend

        bytes32 blkhash = blockhash(blockNum);
        bytes32[] memory publicInputs;
        publicInputs[0] = bytes32(bytes20(to));
        publicInputs[1] = bytes32(amount);
        publicInputs[2] = blkhash;
        if (!IVerifier(verifier).verify(snarkProof, publicInputs)) {
            revert VerificationFailed();
        }

        _mint(to, amount);

    }
}