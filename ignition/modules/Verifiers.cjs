const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("@nomicfoundation/hardhat-toolbox");

module.exports = buildModule("VerifiersModule", (m) => {
  const SmolVerifier = m.contract("SmolVerifier", [], {
    value: 0n,
  });
  const FullVerifier = m.contract("FullVerifier", [], {
    value: 0n,
  });

  const tokenAddress = m.getParameter("tokenAddress");
  console.log("VerifiersModule", {tokenAddress})
  const token = m.contractAt("Token", tokenAddress)
  m.call(token, "setVerifiers", [FullVerifier, SmolVerifier])

  return { FullVerifier, SmolVerifier };
});
