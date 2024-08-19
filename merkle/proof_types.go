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
var CoinList []string

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
	Coins map[string]string
}

type PathNode struct {
	Hash string
	R    int64
	Ub   UserBalance
}

func (t UserBalance) Equal(other UserBalance) bool {
	for i := 0; i < Length; i++ {
		if t.Coins[CoinList[i]] != other.Coins[CoinList[i]] {
			return false
		}
	}
	return true
}

func (t UserBalance) Add(other UserBalance) (UserBalance, error) {
	h := sha1.New()
	if _, err := h.Write([]byte(t.UHash + other.UHash)); err != nil {
		return UserBalance{}, err
	}
	resultUB := UserBalance{
		UHash: hex.EncodeToString(h.Sum(nil)),
	}
	resultUB.Coins = make(map[string]string)
	for i := 0; i < Length; i++ {
		val := CoinList[i]
		v1, err := decimal.NewFromString(t.Coins[val])
		if err != nil {
			return UserBalance{}, err
		}
		v2, err := decimal.NewFromString(other.Coins[val])
		if err != nil {
			return UserBalance{}, err
		}
		resultUB.Coins[val] = v1.Add(v2).RoundDown(8).String()
	}

	return resultUB, nil
}

func NewPath(lNode *PathNode, rNode *PathNode) (*PathNode, error) {
	a, err := lNode.Ub.Add(rNode.Ub)
	if err != nil {
		return nil, err
	}
	var hashString = ""
	for i := 0; i < Length; i++ {
		hashString += a.Coins[CoinList[i]]
	}
	hash, err := hash256(fmt.Sprintf("%s%s%s", lNode.Hash, rNode.Hash, hashString), sha256.New)
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
	ret.Ub.Coins = make(map[string]string)
	bss := strings.Split(jNode.Balances, ",")
	Length = len(bss)
	for i := 0; i < Length; i++ {
		CoinName := strings.Split(bss[i], ":")[0]
		CoinList = append(CoinList, CoinName)
		ret.Ub.Coins[CoinName] = strings.Split(bss[i], ":")[1]
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
