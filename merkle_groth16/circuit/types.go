package circuit

import (
	"merkleverifytool/merkle_groth16/src/utils"

	"github.com/consensys/gnark/frontend"
)

type (
	Variable = frontend.Variable
	API      = frontend.API
)

type CexAssetInfo struct {
	TotalBalance Variable
}

type CexAssetsInfo struct {
	PreCEXTotalEquity  Variable
	PreCEXTotalDebt    Variable
	NextCEXTotalEquity Variable
	NextCEXTotalDebt   Variable
}

type UserInstruction struct {
	PreSMTRoot    Variable
	NextSMTRoot   Variable
	Assets        []Variable
	TotalEquity   Variable
	TotalDebt     Variable
	AccountIndex  Variable
	AccountIdHash Variable
	AccountProof  [utils.AccountTreeDepth]Variable
}
