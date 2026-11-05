# Contract regression tests

Compile for the Paris EVM and execute the Solidity tests on an in-memory Ganache chain:

```sh
npm install --prefix /tmp/ssi-contract-tools --no-save solc@0.8.28 ethers@6 ganache@7
NODE_PATH=/tmp/ssi-contract-tools/node_modules node tests/Contracts/run.cjs
```

The runner uses generated test accounts only. No RPC endpoint, deployed contract or wallet is used.
