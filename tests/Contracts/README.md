# Ownership regression

Install the isolated Node dependencies outside the repository, then execute the
Solidity regression against an in-memory chain (no RPC endpoint or key needed):

```sh
npm install --prefix /tmp/ssi-contract-tests solc@0.8.28 ethers@6 ganache@7
NODE_PATH=/tmp/ssi-contract-tests/node_modules node tests/Contracts/ownership.cjs
```

The runner targets the Paris EVM, including when the host supports Shanghai.
The browser regressions need only Node:

```sh
node --test tests/Frontend/login.test.cjs
```
