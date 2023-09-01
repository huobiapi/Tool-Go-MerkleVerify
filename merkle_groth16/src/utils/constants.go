package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	BatchCreateUserOpsCounts = 5  // batch size
	AccountTreeDepth         = 28 // SMT height
	AssetCounts              = 205
	RedisLockKey             = "prover_mutex_key"
)

var (
	ZeroBigInt                    = new(big.Int).SetInt64(0)
	Uint64MaxValueBigInt, _       = new(big.Int).SetString("18446744073709551616", 10)                    // 2^64
	Uint64MaxValueBigIntSquare, _ = new(big.Int).SetString("340282366920938463463374607431768211456", 10) // 2^128
	Uint64MaxValueFr              = new(fr.Element).SetBigInt(Uint64MaxValueBigInt)                       // 2^64
	Uint64MaxValueFrSquare        = new(fr.Element).SetBigInt(Uint64MaxValueBigIntSquare)                 // 2^128
	AssetTypeForTwoDigits         = map[string]bool{
		"BTTC":  true,
		"SHIB":  true,
		"LUNC":  true,
		"XEC":   true,
		"WIN":   true,
		"BIDR":  true,
		"SPELL": true,
		"HOT":   true,
		"DOGE":  true,
	}
)
