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

	fmt.Println(fmt.Sprintf("Rebuild root BTC balance : %s, root BTC balance in proof file : %s ", node.Ub.Btc, root.Ub.Btc))
	fmt.Println(fmt.Sprintf("Rebuild root ETH+BETH balance : %s, root ETH+BETH balance in proof file: %s ", node.Ub.Eth, root.Ub.Eth))
	fmt.Println(fmt.Sprintf("Rebuild root TRX balance : %s, root TRX balance in proof file: %s ", node.Ub.Trx, root.Ub.Trx))
	fmt.Println(fmt.Sprintf("Rebuild root USDT balance : %s, root USDT balance in proof file: %s ", node.Ub.Usdt, root.Ub.Usdt))
	fmt.Println(fmt.Sprintf("Rebuild root HT balance : %s, root HT balance in proof file: %s ", node.Ub.Ht, root.Ub.Ht))
	fmt.Println(fmt.Sprintf("Rebuild root hash: %s, root hash in proof file: %s ", node.Hash, root.Hash))
	if node.Hash != root.Hash || !node.Ub.Equal(root.Ub) {
		return false, nil
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
