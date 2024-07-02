const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("FullVerifierModule", (m) => {
  const FullVerifier = m.contract("FullVerifier", [], {
    value: 0n,
  });
  return { FullVerifier };
});
