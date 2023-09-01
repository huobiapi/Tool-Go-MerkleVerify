package utils

import "math/big"

type CexAssetInfo struct {
	TotalBalance int64
	Symbol       string
	Index        uint32
}

type CexAssetInfo2 struct {
	TotalEquity uint64
	TotalDebt   uint64
	BasePrice   uint64
	Symbol      string
	Index       uint32
}

type AccountAsset struct {
	Index   uint16
	Balance int64
}

type AccountAsset2 struct {
	Index  uint16
	Equity uint64
	Debt   uint64
}

type AccountInfo struct {
	AccountIndex uint32
	AccountId    []byte
	TotalEquity  *big.Int
	TotalDebt    *big.Int
	Assets       []AccountAsset
}

type AccountInfo2 struct {
	AccountIndex uint32
	AccountId    []byte
	TotalEquity  *big.Int
	TotalDebt    *big.Int
	Assets       []AccountAsset
}

type CreateUserOperation struct {
	BeforeAccountTreeRoot []byte
	AfterAccountTreeRoot  []byte
	Assets                []AccountAsset
	AccountIndex          uint32
	AccountIdHash         []byte
	AccountProof          [AccountTreeDepth][]byte
	TotalEquity           uint64
	TotalDebt             uint64
}

// CreateUserOperation2 备份
type CreateUserOperation2 struct {
	BeforeAccountTreeRoot []byte
	AfterAccountTreeRoot  []byte
	Assets                []AccountAsset
	AccountIndex          uint32
	AccountIdHash         []byte
	AccountProof          [AccountTreeDepth][]byte
}

// CexAssetsTotal new define
type CexAssetsTotal struct {
	BeforeCEXTotalEquity uint64
	AfterCEXTotalEquity  uint64
	BeforeCEXTotalDebt   uint64
	AfterCEXTotalDebt    uint64
}

type BatchCreateUserWitness struct {
	BatchCommitment           []byte
	BeforeAccountTreeRoot     []byte
	AfterAccountTreeRoot      []byte
	BeforeCEXAssetsCommitment []byte
	AfterCEXAssetsCommitment  []byte

	BeforeCexAssets []CexAssetInfo
	CreateUserOps   []CreateUserOperation
	TotalCexAssets  CexAssetsTotal
}

type BatchCreateUserWitness2 struct {
	BatchCommitment           []byte
	BeforeAccountTreeRoot     []byte
	AfterAccountTreeRoot      []byte
	BeforeCEXAssetsCommitment []byte
	AfterCEXAssetsCommitment  []byte

	BeforeCexAssets []CexAssetInfo
	CreateUserOps   []CreateUserOperation
}
