const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("@nomicfoundation/hardhat-toolbox");

module.exports = buildModule("VerifiersModule", (m) => {
  const RemintVerifier = m.contract("RemintVerifier", [], {
    value: 0n,
  });
  const StorageRootVerifier = m.contract("StorageRootVerifier", [], {
    value: 0n,
  });

  const tokenAddress = m.getParameter("tokenAddress");
  const token = m.contractAt("Token", tokenAddress)
  m.call(token, "setVerifiers", [StorageRootVerifier, RemintVerifier])

  return { StorageRootVerifier, RemintVerifier };
});
