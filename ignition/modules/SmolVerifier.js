const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("SmolVerifierModule", (m) => {
  const token = m.contract("SmolVerifier", [], {
    value: 0n,
  });
  return { token };
});
