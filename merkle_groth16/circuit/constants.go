package circuit

import "math/big"

var (
	//  is poseidon hash(empty account info)
	EmptyAccountLeafNodeHash, _ = new(big.Int).SetString("05b03718e844609464db69f0f4f7eb7daf0e4c765f3575978b57cb0a4750a43e", 16)
)
