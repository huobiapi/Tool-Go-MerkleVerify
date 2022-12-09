# Huobi Merkle Verify Tool

## Background

Huobi launches [Proof of Reserves (PoR)]() to improve the security and transparency of user's assets. These tools will allow
you to verify the validity of your assets in the merkle sum tree by verify merkle proof file, in order to confirm your assets in Huobi.

## Introduction

### Building the source

Download the [latest build](https://github.com/huobiapi/Tool-Go-MerkleVerify/releases) for your operating system and architecture. Also, you can build the source by yourself.

Building this open source tool requires Go (version >= 1.16).

Install dependencies
```shell
 go mod vendor
```

build
```shell
 make
```

run
```shell
./build/MerkleVerify --file ./merkle_sum_proof.json
```
