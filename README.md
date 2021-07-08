# Impact analysis of neutering the `SELFDESTRUCT` opcode in Ethereum

## Chain data retrieval

In order to retrive chain data, I am running a local Geth node. Since I don't have the luxury of running an archive node, I have also retrieved data from the public `crypto_ethereum` Google BigQuery dataset, and Infura. In addition, I have fetched solidity code from etherscan.io.

## Results

There have been a total of 43,621,454 contract deployments on Ethereum Mainnet (as of June 12, 2021). Note that some of these contracts may have selfdestructed and no longer exist. Also note that there may be more than one deployment to the same contract address (see *Redeployable contracts* below), in which case we count each deployment separately. The contracts have 398,220 distinct bytecodes. Among the distinct codes, there are

* 20,565 (~5%) distinct bytecodes having the `SELFDESTRUCT` opcode,
* 32,032 (~8%) distinct bytecodes that do not have `SELFDESTRUCT`, but has either `CALLCODE` or `DELEGATECALL`, and
* 345,623 (~87%) distinct bytecodes that do not have any of the three opcodes and are therefore indestructable.

The bytecodes that contain either `SELFDESTRUCT`, `CALLCODE` or `DELEGATECALL` are labeled *destructible*. We define a contract to be destructible if its bytecode is destructible.

(Note: All contracts that are able to selfdestruct are labeled destructible, but not all contracts that are labeled destructible are actually able to selfdestruct)

Among the 43,621,454 total deployed contracts, 

### Redeployable contracts

Redeployable contracts are contracts that may selfdestruct, and where it is possible to deploy a new contract at the same address. For a contract to be redeployable it must be selfdestructible, and either

 1. the contract was deployed with `CREATE2` or
 2. the contract was deployed with `CREATE` by a redeployable contract.

We could analyze traces from an archive node to determine if a contract was deployed with `CREATE2`. Unfortunately I do not have an archive node, but I do have information about which contract created which, from the `traces` table in the BigQuery dataset. I was then able to identify potentially redeployabe contracts by checking if the contract was deployed by a contract that could be proven to only create contracts using `CREATE2`. This can be proven if the creating contract contains `CREATE2`, and do not contain either `CREATE`, `CALLCODE` or `DELEGATECALL`. Using this method I was able to find 11,592,420 destructible contracts that are proven to have been deployed using `CREATE2`, and could possibly be redeployable (but there might be more). There seems to be a lot of false positives here. For instance, the contract [0x0000000000004946c0e9f43f4dee607b0ef1fa1c](https://etherscan.io/address/0x0000000000004946c0e9f43f4dee607b0ef1fa1c#contracts) (Chi Gastoken) has deployed 10,206,621 destructible contracts using `CREATE2`, but they are all created at different addresses, so I would assume that they are not redeployable (although I haven't checked).

#### Historical redeployments

Instead of trying to find all currently existing redeployable contracts, we also analyzed the cases where redeployments have happened in the past. TODO

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
