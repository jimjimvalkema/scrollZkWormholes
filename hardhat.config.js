// type: "module" not supported in package.js which is cringe
require("@nomicfoundation/hardhat-toolbox");
const { vars } = require("hardhat/config");

const SEPOLIA_SCROLL_ETHERSCAN_KEY = vars.get("SEPOLIA_SCROLL_ETHERSCAN_KEY");
const PRIVATE_KEY = vars.get("PRIVATE_KEY");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.23",
  // https://docs.scroll.io/en/developers/developer-quickstart/#hardhat
  networks: {
    scrollSepolia: {
      url: "https://sepolia-rpc.scroll.io/" || "",
      accounts:
        [PRIVATE_KEY]
    },
  },
  etherscan: {
    apiKey: {
      scrollSepolia:SEPOLIA_SCROLL_ETHERSCAN_KEY,
    },
    customChains: [
      {
        network: 'scrollSepolia',
        chainId: 534351,
        urls: {
          apiURL: 'https://api-sepolia.scrollscan.com/api',
          browserURL: 'https://sepolia.scrollscan.com/',
        },
      },
    ],
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },

  solidity: {
    version: "0.8.23",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
};
