package merkle

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

var Length int

type JsonProofPath struct {
	Path []*JsonProofNode `json:"data"`
}

type JsonProofNode struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	UHash    string `json:"uhash"`
	Depth    int    `json:"depth"`
	R        int64  `json:"r"`
	Balances string `json:"balances"`
}

type UserBalance struct {
	UHash string
	Btc   string
	Eth   string
	Trx   string
	Usdt  string
	Ht    string
	Xrp   string
	Doge  string
	Sol   string
}

type PathNode struct {
	Hash string
	R    int64
	Ub   UserBalance
}

func (t UserBalance) Equal(other UserBalance) bool {
	var result bool
	result = t.Btc == other.Btc &&
		t.Eth == other.Eth &&
		t.Trx == other.Trx &&
		t.Usdt == other.Usdt &&
		t.Ht == other.Ht
	if Length > 5 {
		result = result && t.Xrp == other.Xrp &&
			t.Doge == other.Doge &&
			t.Sol == other.Sol
	}
	return result
}

func (t UserBalance) Add(other UserBalance) (UserBalance, error) {
	btc1, err := decimal.NewFromString(t.Btc)
	if err != nil {
		return UserBalance{}, err
	}
	eth1, err := decimal.NewFromString(t.Eth)
	if err != nil {
		return UserBalance{}, err
	}
	trx1, err := decimal.NewFromString(t.Trx)
	if err != nil {
		return UserBalance{}, err
	}
	usdt1, err := decimal.NewFromString(t.Usdt)
	if err != nil {
		return UserBalance{}, err
	}
	ht1, err := decimal.NewFromString(t.Ht)
	if err != nil {
		return UserBalance{}, err
	}

	btc2, err := decimal.NewFromString(other.Btc)
	if err != nil {
		return UserBalance{}, err
	}
	eth2, err := decimal.NewFromString(other.Eth)
	if err != nil {
		return UserBalance{}, err
	}
	trx2, err := decimal.NewFromString(other.Trx)
	if err != nil {
		return UserBalance{}, err
	}
	usdt2, err := decimal.NewFromString(other.Usdt)
	if err != nil {
		return UserBalance{}, err
	}
	ht2, err := decimal.NewFromString(other.Ht)
	if err != nil {
		return UserBalance{}, err
	}

	h := sha1.New()
	if _, err := h.Write([]byte(t.UHash + other.UHash)); err != nil {
		return UserBalance{}, err
	}
	resultUB := UserBalance{
		UHash: hex.EncodeToString(h.Sum(nil)),
		Btc:   btc1.Add(btc2).RoundDown(8).String(),
		Eth:   eth1.Add(eth2).RoundDown(8).String(),
		Trx:   trx1.Add(trx2).RoundDown(8).String(),
		Usdt:  usdt1.Add(usdt2).RoundDown(8).String(),
		Ht:    ht1.Add(ht2).RoundDown(8).String(),
	}
	if Length > 5 {
		xrp1, err := decimal.NewFromString(t.Xrp)
		if err != nil {
			return UserBalance{}, err
		}
		doge1, err := decimal.NewFromString(t.Doge)
		if err != nil {
			return UserBalance{}, err
		}
		sol1, err := decimal.NewFromString(t.Sol)
		if err != nil {
			return UserBalance{}, err
		}
		xrp2, err := decimal.NewFromString(other.Xrp)
		if err != nil {
			return UserBalance{}, err
		}
		doge2, err := decimal.NewFromString(other.Doge)
		if err != nil {
			return UserBalance{}, err
		}
		sol2, err := decimal.NewFromString(other.Sol)
		if err != nil {
			return UserBalance{}, err
		}
		resultUB.Xrp = xrp1.Add(xrp2).RoundDown(8).String()
		resultUB.Doge = doge1.Add(doge2).RoundDown(8).String()
		resultUB.Sol = sol1.Add(sol2).RoundDown(8).String()
	}
	return resultUB, nil
}

func NewPath(lNode *PathNode, rNode *PathNode) (*PathNode, error) {
	a, err := lNode.Ub.Add(rNode.Ub)
	if err != nil {
		return nil, err
	}

	hash, err := hash256(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s", lNode.Hash, rNode.Hash, a.Btc, a.Eth, a.Trx, a.Usdt, a.Ht, a.Xrp, a.Doge, a.Sol), sha256.New)
	if err != nil {
		return nil, err
	}

	return &PathNode{Hash: hex.EncodeToString(hash), Ub: a}, nil
}

type PathNodes struct {
	Path []*PathNode
}

func (jNode *JsonProofNode) JsonProofNodeToPathNode() *PathNode {
	ret := &PathNode{}
	ret.Hash = jNode.Hash
	ret.R = jNode.R
	ret.Ub.UHash = jNode.UHash
	bss := strings.Split(jNode.Balances, ",")
	Length = len(bss)

	ret.Ub.Btc = strings.Split(bss[0], ":")[1]
	ret.Ub.Eth = strings.Split(bss[1], ":")[1]
	ret.Ub.Trx = strings.Split(bss[2], ":")[1]
	ret.Ub.Usdt = strings.Split(bss[3], ":")[1]
	ret.Ub.Ht = strings.Split(bss[4], ":")[1]
	if Length > 5 {
		ret.Ub.Xrp = strings.Split(bss[5], ":")[1]
		ret.Ub.Doge = strings.Split(bss[6], ":")[1]
		ret.Ub.Sol = strings.Split(bss[7], ":")[1]
	}

	return ret
}

func (jPath *JsonProofPath) JsonProofPathToPathNodes() *PathNodes {
	ret := new(PathNodes)
	ret.Path = make([]*PathNode, 0)
	for _, jp := range jPath.Path {
		ret.Path = append(ret.Path, jp.JsonProofNodeToPathNode())
	}
	return ret
}
