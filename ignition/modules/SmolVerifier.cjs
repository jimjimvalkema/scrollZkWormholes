const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("SmolVerifierModule", (m) => {
  const FullVerifier = m.contract("SmolVerifier", [], {
    value: 0n,
  });
  return { FullVerifier };
});
