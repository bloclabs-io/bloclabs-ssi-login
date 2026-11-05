# Contract regression tests

Install the isolated Node dependencies outside the repository, then compile for
the Paris EVM and run both Solidity regressions on an in-memory Ganache chain:

```sh
npm install --prefix /tmp/ssi-contract-tests --no-save solc@0.8.28 ethers@6 ganache@7
NODE_PATH=/tmp/ssi-contract-tests/node_modules node tests/Contracts/run.cjs
NODE_PATH=/tmp/ssi-contract-tests/node_modules node tests/Contracts/ownership.cjs
```

Both runners target Paris, including when the host supports Shanghai, and use
generated test accounts only. No RPC endpoint, deployed contract or wallet is used.

The browser regressions need only Node:

```sh
node --test tests/Frontend/login.test.cjs
```
