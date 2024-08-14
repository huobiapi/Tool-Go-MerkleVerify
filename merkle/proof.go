package merkle

import (
	"errors"
	"fmt"
	"hash"
)

func hash256(hash string, hashStrategy func() hash.Hash) ([]byte, error) {
	h := hashStrategy()
	if _, err := h.Write([]byte(hash)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func VerifyProof(m *PathNodes) (bool, error) {
	if len(m.Path) < 3 {
		return false, errors.New("invalid path")
	}
	self := m.Path[len(m.Path)-1]
	var lNode, rNode *PathNode
	if self.R == 1 {
		lNode, rNode = m.Path[1], self
	} else {
		lNode, rNode = self, m.Path[1]
	}

	node, err := NewPath(lNode, rNode)
	if err != nil {
		return false, err
	}

	for i := 2; i < len(m.Path)-1; i++ {
		if m.Path[i].R == 1 {
			lNode, rNode = node, m.Path[i]
		} else {
			lNode, rNode = m.Path[i], node
		}
		node, err = NewPath(lNode, rNode)
		if err != nil {
			return false, err
		}
	}

	root := m.Path[0]

	fmt.Printf("Rebuild root BTC balance : %s, root BTC balance in proof file : %s \n", node.Ub.Btc, root.Ub.Btc)
	fmt.Printf("Rebuild root ETH+BETH+stETH balance : %s, root ETH+BETH+stETH balance in proof file: %s \n", node.Ub.Eth, root.Ub.Eth)
	fmt.Printf("Rebuild root TRX balance : %s, root TRX balance in proof file: %s \n", node.Ub.Trx, root.Ub.Trx)
	fmt.Printf("Rebuild root USDT+stUSDT+aETHUSDT balance : %s, root USDT+stUSDT+aETHUSDT balance in proof file: %s \n", node.Ub.Usdt, root.Ub.Usdt)
	fmt.Printf("Rebuild root HTX balance : %s, root HTX balance in proof file: %s \n", node.Ub.Ht, root.Ub.Ht)
	if Length > 5 {
		fmt.Printf("Rebuild root XRP balance : %s, root XRP balance in proof file: %s \n", node.Ub.Xrp, root.Ub.Xrp)
		fmt.Printf("Rebuild root DOGE balance : %s, root DOGE balance in proof file: %s \n", node.Ub.Doge, root.Ub.Doge)
		fmt.Printf("Rebuild root SOL balance : %s, root SOL balance in proof file: %s \n", node.Ub.Sol, root.Ub.Sol)
	}

	fmt.Printf("Rebuild root hash: %s, root hash in proof file: %s \n", node.Hash, root.Hash)

	if node.Hash != root.Hash || !node.Ub.Equal(root.Ub) {
		return false, err
	}
	return true, nil
}

func VerifyProofFile(pf *JsonProofPath) (bool, error) {
	verified, err := VerifyProof(pf.JsonProofPathToPathNodes())
	if verified {
		return true, nil
	}

	return false, err
}
