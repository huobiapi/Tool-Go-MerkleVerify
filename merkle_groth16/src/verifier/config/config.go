package config

import (
	"math/big"
	"merkleverifytool/merkle_groth16/src/utils"
)

type Config struct {
	ProofTable    string
	ZkKeyName     string
	CexAssetsInfo []utils.CexAssetInfo
}

type UserConfig struct {
	AccountIndex  uint32
	AccountIdHash string
	TotalEquity   big.Int
	TotalDebt     big.Int
	Root          string
	Assets        []utils.AccountAsset
	Proof         []string
}
