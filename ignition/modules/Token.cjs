const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// const JAN_1ST_2030 = 1893456000;
// const ONE_GWEI = 1_000_000_000n;

module.exports = buildModule("TokenModule", (m) => {
  // const unlockTime = m.getParameter("unlockTime", JAN_1ST_2030);
  // const lockedAmount = m.getParameter("lockedAmount", ONE_GWEI);
  const SmolVerifier = m.contract("SmolVerifier", [], {
    value: 0n,
  });
  const FullVerifier = m.contract("FullVerifier", [], {
    value: 0n,
  });

  const token = m.contract("Token", [], {
    value: 0n,
  });
  m.call(token, "setVerifiers", [FullVerifier, SmolVerifier])


  return { token, FullVerifier, SmolVerifier };
});
