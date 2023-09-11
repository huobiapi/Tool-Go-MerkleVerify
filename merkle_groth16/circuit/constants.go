package circuit

import "math/big"

var (
	//  is poseidon hash(empty account info)
	EmptyAccountLeafNodeHash, _ = new(big.Int).SetString("0cc1c37a517c3b8db148653c41b15dc7f0136dc284fb2818adf26669d897298c", 16)
)
