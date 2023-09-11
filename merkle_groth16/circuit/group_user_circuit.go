package circuit

import (
	"merkleverifytool/merkle_groth16/src/utils"

	"github.com/consensys/gnark/std/hash/poseidon"
)

type GroupUserCircuit struct {
	GroupCommitment   Variable `gnark:",public"`
	PreSMTRoot        Variable
	NextSMTRoot       Variable
	PreCEXCommitment  Variable
	NextCEXCommitment Variable
	PreCexAssets      []CexAssetInfo
	TotalCexAssets    CexAssetsInfo
	UserInstructions  []UserInstruction
}

func NewVerifyBatchCreateUserCircuit(commitment []byte) *GroupUserCircuit {
	var v GroupUserCircuit
	v.GroupCommitment = commitment
	return &v
}

func NewBatchCreateUserCircuit(assetCounts uint32, batchCounts uint32) *GroupUserCircuit {
	var circuit GroupUserCircuit
	circuit.GroupCommitment = 0
	circuit.PreSMTRoot = 0
	circuit.NextSMTRoot = 0
	circuit.PreCEXCommitment = 0
	circuit.NextCEXCommitment = 0
	circuit.TotalCexAssets.PreCEXTotalEquity = 0
	circuit.TotalCexAssets.NextCEXTotalEquity = 0
	circuit.TotalCexAssets.PreCEXTotalDebt = 0
	circuit.TotalCexAssets.NextCEXTotalDebt = 0
	circuit.PreCexAssets = make([]CexAssetInfo, assetCounts)
	for i := uint32(0); i < assetCounts; i++ {
		circuit.PreCexAssets[i].TotalBalance = 0
	}
	circuit.UserInstructions = make([]UserInstruction, batchCounts)
	for i := uint32(0); i < batchCounts; i++ {
		circuit.UserInstructions[i] = UserInstruction{
			PreSMTRoot:   0,
			NextSMTRoot:  0,
			Assets:       make([]Variable, assetCounts),
			AccountIndex: 0,
			AccountProof: [utils.AccountTreeDepth]Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		}
		for j := uint32(0); j < assetCounts; j++ {
			circuit.UserInstructions[i].Assets[j] = 0
		}
	}
	return &circuit
}

func (b GroupUserCircuit) Define(api API) error {
	// verify whether GroupCommitment is computed correctly
	actualBatchCommitment := poseidon.Poseidon(api, b.PreSMTRoot, b.NextSMTRoot, b.PreCEXCommitment, b.NextCEXCommitment)
	api.AssertIsEqual(b.GroupCommitment, actualBatchCommitment)
	cexAssets := make([]Variable, len(b.PreCexAssets))
	afterCexAssets := make([]Variable, len(b.PreCexAssets))
	for i := 0; i < len(b.PreCexAssets); i++ {
		cexAssets[i] = b.PreCexAssets[i].TotalBalance
		afterCexAssets[i] = b.PreCexAssets[i].TotalBalance //
	}
	actualCexAssetsCommitment := ComputeUserAssetsCommitment(api, cexAssets)
	api.AssertIsEqual(b.PreCEXCommitment, actualCexAssetsCommitment)

	api.AssertIsEqual(b.PreSMTRoot, b.UserInstructions[0].PreSMTRoot)
	api.AssertIsEqual(b.NextSMTRoot, b.UserInstructions[len(b.UserInstructions)-1].NextSMTRoot)

	tempTotalCexAssets := CexAssetsInfo{
		PreCEXTotalEquity:  0,
		PreCEXTotalDebt:    0,
		NextCEXTotalEquity: b.TotalCexAssets.PreCEXTotalEquity,
		NextCEXTotalDebt:   b.TotalCexAssets.PreCEXTotalDebt,
	}
	CheckValueInRange(api, b.TotalCexAssets.PreCEXTotalDebt)
	CheckValueInRange(api, b.TotalCexAssets.PreCEXTotalEquity)

	for i := 0; i < len(b.UserInstructions); i++ {
		accountIndexHelper := AccountIdToMerkleHelper(api, b.UserInstructions[i].AccountIndex)
		VerifyMerkleProof(api, b.UserInstructions[i].PreSMTRoot, EmptyAccountLeafNodeHash, b.UserInstructions[i].AccountProof[:], accountIndexHelper)
		userAssets := b.UserInstructions[i].Assets //copy

		for j := 0; j < len(userAssets); j++ {
			afterCexAssets[j] = api.Add(afterCexAssets[j], userAssets[j])
		}
		tempTotalCexAssets.NextCEXTotalEquity = api.Add(tempTotalCexAssets.NextCEXTotalEquity, b.UserInstructions[i].TotalEquity)
		tempTotalCexAssets.NextCEXTotalDebt = api.Add(tempTotalCexAssets.NextCEXTotalDebt, b.UserInstructions[i].TotalDebt)
		api.AssertIsLessOrEqual(tempTotalCexAssets.NextCEXTotalDebt, tempTotalCexAssets.NextCEXTotalEquity)
		CheckValueInRange(api, b.UserInstructions[i].TotalEquity)
		CheckValueInRange(api, b.UserInstructions[i].TotalDebt)
		userAssetsCommitment := ComputeUserAssetsCommitment(api, userAssets)
		accountHash := poseidon.Poseidon(api, b.UserInstructions[i].AccountIdHash, b.UserInstructions[i].TotalEquity, b.UserInstructions[i].TotalDebt, userAssetsCommitment)
		actualAccountTreeRoot := UpdateMerkleProof(api, accountHash, b.UserInstructions[i].AccountProof[:], accountIndexHelper)
		api.AssertIsEqual(actualAccountTreeRoot, b.UserInstructions[i].NextSMTRoot)
	}
	CheckValueInRange(api, tempTotalCexAssets.NextCEXTotalDebt)
	api.AssertIsEqual(tempTotalCexAssets.NextCEXTotalEquity, b.TotalCexAssets.NextCEXTotalEquity)
	api.AssertIsEqual(tempTotalCexAssets.NextCEXTotalDebt, b.TotalCexAssets.NextCEXTotalDebt)
	actualAfterCEXAssetsCommitment := ComputeUserAssetsCommitment(api, afterCexAssets)
	api.AssertIsEqual(actualAfterCEXAssetsCommitment, b.NextCEXCommitment)
	for i := 0; i < len(b.UserInstructions)-1; i++ {
		api.AssertIsEqual(b.UserInstructions[i].NextSMTRoot, b.UserInstructions[i+1].PreSMTRoot)
	}

	return nil
}

func SetBatchCreateUserCircuitWitness(batchWitness *utils.BatchCreateUserWitness) (witness *GroupUserCircuit, err error) {
	witness = &GroupUserCircuit{
		GroupCommitment:   batchWitness.BatchCommitment,
		PreSMTRoot:        batchWitness.BeforeAccountTreeRoot,
		NextSMTRoot:       batchWitness.AfterAccountTreeRoot,
		PreCEXCommitment:  batchWitness.BeforeCEXAssetsCommitment,
		NextCEXCommitment: batchWitness.AfterCEXAssetsCommitment,
		PreCexAssets:      make([]CexAssetInfo, len(batchWitness.BeforeCexAssets)),
		UserInstructions:  make([]UserInstruction, len(batchWitness.CreateUserOps)),
	}
	witness.TotalCexAssets.PreCEXTotalEquity = batchWitness.TotalCexAssets.BeforeCEXTotalEquity
	witness.TotalCexAssets.PreCEXTotalDebt = batchWitness.TotalCexAssets.BeforeCEXTotalDebt
	witness.TotalCexAssets.NextCEXTotalEquity = batchWitness.TotalCexAssets.AfterCEXTotalEquity
	witness.TotalCexAssets.NextCEXTotalDebt = batchWitness.TotalCexAssets.AfterCEXTotalDebt

	for i := 0; i < len(witness.PreCexAssets); i++ {
		witness.PreCexAssets[i].TotalBalance = batchWitness.BeforeCexAssets[i].TotalBalance //___

	}
	for i := 0; i < len(witness.UserInstructions); i++ {
		witness.UserInstructions[i].PreSMTRoot = batchWitness.CreateUserOps[i].BeforeAccountTreeRoot
		witness.UserInstructions[i].NextSMTRoot = batchWitness.CreateUserOps[i].AfterAccountTreeRoot
		witness.UserInstructions[i].Assets = make([]Variable, len(batchWitness.CreateUserOps[i].Assets))
		witness.UserInstructions[i].TotalEquity = batchWitness.CreateUserOps[i].TotalEquity
		witness.UserInstructions[i].TotalDebt = batchWitness.CreateUserOps[i].TotalDebt

		for j := 0; j < len(batchWitness.CreateUserOps[i].Assets); j++ {
			var userAsset Variable
			userAsset = batchWitness.CreateUserOps[i].Assets[j].Balance
			witness.UserInstructions[i].Assets[j] = userAsset
		}
		witness.UserInstructions[i].AccountIdHash = batchWitness.CreateUserOps[i].AccountIdHash
		witness.UserInstructions[i].AccountIndex = batchWitness.CreateUserOps[i].AccountIndex
		for j := 0; j < len(witness.UserInstructions[i].AccountProof); j++ {
			witness.UserInstructions[i].AccountProof[j] = batchWitness.CreateUserOps[i].AccountProof[j]
		}
	}
	return witness, nil
}
