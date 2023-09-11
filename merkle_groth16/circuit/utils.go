package circuit

import (
	"math/big"
	"merkleverifytool/merkle_groth16/src/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon"
)

func VerifyMerkleProof(api API, merkleRoot Variable, node Variable, proofSet, helper []Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = poseidon.Poseidon(api, d1, d2)
	}
	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(merkleRoot, node)
}

func UpdateMerkleProof(api API, node Variable, proofSet, helper []Variable) (root Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = poseidon.Poseidon(api, d1, d2)
	}
	root = node
	return root
}

func AccountIdToMerkleHelper(api API, accountId Variable) []Variable {
	merkleHelpers := api.ToBinary(accountId, utils.AccountTreeDepth)
	return merkleHelpers
}

// check value is in [0, 2^64-1] range
func CheckValueInRange(api API, value Variable) {
	api.ToBinary(value, 64)
}

func Abs(api frontend.API, i frontend.Variable) frontend.Variable {
	// _v + 2 ** 66 - bound
	// _v should be less than 2 ** 66
	// bound should be less than 2 ** 66
	temp := api.Add(i, new(big.Int).Exp(new(big.Int).SetUint64(2), new(big.Int).SetInt64(int64(68-2)), nil))
	bitsTemp := api.ToBinary(temp, 68)
	cmResult := bitsTemp[68-2]
	return api.Select(cmResult, i, api.Neg(i))

}

func ComputeUserAssetsCommitment(api API, assets []Variable) Variable {
	assets_ := make([]frontend.Variable, len(assets))
	for i := 0; i < len(assets); i++ {
		assets_[i] = Abs(api, assets[i])
	}
	commitment := poseidon.Poseidon(api, assets_...)
	return commitment
}
