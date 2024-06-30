const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// const JAN_1ST_2030 = 1893456000;
// const ONE_GWEI = 1_000_000_000n;
const VERIFIER_ADDRESS = "0xb92D48147Af9db3A94EB0067761DA1AA9B7188AC"

module.exports = buildModule("TokenModule", (m) => {
  // const unlockTime = m.getParameter("unlockTime", JAN_1ST_2030);
  // const lockedAmount = m.getParameter("lockedAmount", ONE_GWEI);

  const token = m.contract("Token", [VERIFIER_ADDRESS], {
    value: 0n,
  });

  return { token };
});
