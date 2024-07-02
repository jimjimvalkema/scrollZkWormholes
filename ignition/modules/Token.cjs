const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("TokenModule", (m) => {
  const token = m.contract("Token", [], {
    value: 0n,
  });
  return { token };
});