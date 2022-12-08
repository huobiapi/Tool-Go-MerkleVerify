package merkle

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shopspring/decimal"
	"log"
	"strings"
)

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
}

type PathNode struct {
	Hash string
	R    int64
	Ub   UserBalance
}

func (t UserBalance) Equal(other UserBalance) bool {
	return t.Btc == other.Btc &&
		t.Eth == other.Eth &&
		t.Trx == other.Trx &&
		t.Usdt == other.Usdt &&
		t.Ht == other.Ht

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
	return UserBalance{
		UHash: hex.EncodeToString(h.Sum(nil)),
		Btc:   fmt.Sprintf("%s", btc1.Add(btc2).RoundDown(8).String()),
		Eth:   fmt.Sprintf("%s", eth1.Add(eth2).RoundDown(8).String()),
		Trx:   fmt.Sprintf("%s", trx1.Add(trx2).RoundDown(8).String()),
		Usdt:  fmt.Sprintf("%s", usdt1.Add(usdt2).RoundDown(8).String()),
		Ht:    fmt.Sprintf("%s", ht1.Add(ht2).RoundDown(8).String()),
	}, nil
}

func NewPath(lNode *PathNode, rNode *PathNode) (*PathNode, error) {
	a, err := lNode.Ub.Add(rNode.Ub)
	if err != nil {
		return nil, err
	}

	hash, err := hash256(fmt.Sprintf("%s%s%s%s%s%s%s", lNode.Hash, rNode.Hash, a.Btc, a.Eth, a.Trx, a.Usdt, a.Ht), sha256.New)
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
	if len(bss) != 5 {
		log.Fatal(errors.New("invalid balance"))
	}

	btc := strings.Split(bss[0], ":")
	eth := strings.Split(bss[1], ":")
	trx := strings.Split(bss[2], ":")
	usdt := strings.Split(bss[3], ":")
	ht := strings.Split(bss[4], ":")
	if len(btc) != 2 || len(eth) != 2 || len(trx) != 2 || len(usdt) != 2 || len(ht) != 2 {
		log.Fatal(errors.New("invalid balance"))
	}

	ret.Ub.Btc = btc[1]
	ret.Ub.Eth = eth[1]
	ret.Ub.Trx = trx[1]
	ret.Ub.Usdt = usdt[1]
	ret.Ub.Ht = ht[1]

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
