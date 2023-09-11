package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/shopspring/decimal"
	//"crypto/sha1"
)

func ConvertAssetInfoToBytes(value any) []byte {
	switch t := value.(type) {
	case CexAssetInfo:
		balanceBigInt := new(big.Int).SetInt64(t.TotalBalance)
		return balanceBigInt.Bytes()
	default:
		panic("not supported type")
	}
}

func SelectAssetValue(expectAssetIndex int, currentAssetPosition int, assets []AccountAsset) (*big.Int, bool) {
	if currentAssetPosition >= len(assets) {
		return ZeroBigInt, false
	} else {
		return new(big.Int).SetInt64(assets[currentAssetPosition].Balance), true
	}
}

func ComputeUserAssetsCommitment(hasher *hash.Hash, assets []AccountAsset) []byte {
	(*hasher).Reset()
	userAssets := make([]AccountAsset, AssetCounts)
	for p := 0; p < len(assets); p++ {
		userAssets[assets[p].Index] = assets[p]
	}
	for i := 0; i < AssetCounts; i++ {
		(*hasher).Write(new(big.Int).SetInt64(userAssets[i].Balance).Bytes())
	}
	return (*hasher).Sum(nil)
}

func ParseUserDataSet(dirname string) ([]AccountInfo, []CexAssetInfo, error) {
	userFiles, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, nil, err
	}
	var accountInfo []AccountInfo
	var cexAssetInfo []CexAssetInfo

	workersNum := 8
	userFileNames := make([]string, 0)

	type UserParseRes struct {
		accounts []AccountInfo
		cex      []CexAssetInfo
		index    int
	}
	results := make([]chan UserParseRes, workersNum)
	for i := 0; i < workersNum; i++ {
		results[i] = make(chan UserParseRes, 1)
	}
	for _, userFile := range userFiles {
		if strings.Index(userFile.Name(), ".csv") == -1 {
			continue
		}
		userFileNames = append(userFileNames, filepath.Join(dirname, userFile.Name()))
	}
	for i := 0; i < workersNum; i++ {
		go func(workerId int) {
			for j := workerId; j < len(userFileNames); j += workersNum {
				if j >= len(userFileNames) {
					break
				}
				tmpAccountInfo, tmpCexAssetInfo, err := ReadUserDataFromCsvFile(userFileNames[j])
				if err != nil {
					panic(err.Error())
				}
				results[workerId] <- UserParseRes{
					accounts: tmpAccountInfo,
					cex:      tmpCexAssetInfo,
				}
			}
		}(i)
	}

	gcQuitChan := make(chan bool)
	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
				runtime.GC()
			case <-gcQuitChan:
				return
			}
		}
	}()

	quit := make(chan bool)
	go func() {
		for i := 0; i < len(userFileNames); i++ {
			res := <-results[i%workersNum]
			if i != 0 {
				for j := 0; j < len(res.accounts); j++ {
					res.accounts[j].AccountIndex += uint32(len(accountInfo))
				}
			}
			accountInfo = append(accountInfo, res.accounts...)
			if len(cexAssetInfo) == 0 {
				cexAssetInfo = res.cex
			}
		}
		quit <- true
	}()
	<-quit
	gcQuitChan <- true
	return accountInfo, cexAssetInfo, nil
}

func ParseUserDataSet2(dirname string) ([]AccountInfo, []CexAssetInfo, error) {
	userFiles, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, nil, err
	}
	var accountInfo []AccountInfo
	var cexAssetInfo []CexAssetInfo

	workersNum := 8
	userFileNames := make([]string, 0)

	type UserParseRes struct {
		accounts []AccountInfo
		cex      []CexAssetInfo
		index    int
	}
	results := make([]chan UserParseRes, workersNum)
	for i := 0; i < workersNum; i++ {
		results[i] = make(chan UserParseRes, 1)
	}
	for _, userFile := range userFiles {
		if strings.Index(userFile.Name(), ".csv") == -1 {
			continue
		}
		userFileNames = append(userFileNames, filepath.Join(dirname, userFile.Name()))
	}
	for i := 0; i < workersNum; i++ {
		go func(workerId int) {
			for j := workerId; j < len(userFileNames); j += workersNum {
				if j >= len(userFileNames) {
					break
				}
				tmpAccountInfo, tmpCexAssetInfo, err := ReadUserDataFromCsvFile(userFileNames[j])
				if err != nil {
					panic(err.Error())
				}
				results[workerId] <- UserParseRes{
					accounts: tmpAccountInfo,
					cex:      tmpCexAssetInfo,
				}
			}
		}(i)
	}

	gcQuitChan := make(chan bool)
	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
				runtime.GC()
			case <-gcQuitChan:
				return
			}
		}
	}()

	quit := make(chan bool)
	go func() {
		for i := 0; i < len(userFileNames); i++ {
			res := <-results[i%workersNum]
			if i != 0 {
				for j := 0; j < len(res.accounts); j++ {
					res.accounts[j].AccountIndex += uint32(len(accountInfo))
				}
			}
			accountInfo = append(accountInfo, res.accounts...)
			if len(cexAssetInfo) == 0 {
				cexAssetInfo = res.cex
			}
		}
		quit <- true
	}()
	<-quit
	gcQuitChan <- true
	return accountInfo, cexAssetInfo, nil
}

func SafeAdd(a uint64, b uint64) (c uint64) {
	c = a + b
	if b < 0 && a < 0 {
		if c > a || c > b {
			panic("overflow for balance")
		}
	} else if b > 0 && a > 0 {
		if c < a || c < b {
			panic("overflow for balance")
		}
	}
	return c
}

func SafeAddInt64(a int64, b int64) (c int64) {
	c = a + b
	if b < 0 && a < 0 {
		if c > a || c > b {
			panic("overflow for balance")
		}
	} else if b > 0 && a > 0 {
		if c < a || c < b {
			panic("overflow for balance")
		}
	}
	return c
}

func HashBytesForUID(uid string) (accountId []byte) {
	hash := sha256.New()
	hash.Write([]byte(uid))
	accountId = hash.Sum(nil)
	return accountId
}

func ReadUserDataFromCsvFile(name string) ([]AccountInfo, []CexAssetInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	accountIndex := 0
	cexAssetsInfo := make([]CexAssetInfo, AssetCounts)
	accounts := make([]AccountInfo, len(data)-1)
	symbols := data[0]
	data = data[1:]
	for i := 0; i < AssetCounts; i++ {
		cexAssetsInfo[i].Symbol = strings.Split(symbols[i+2], "_")[0]
		cexAssetsInfo[i].Index = uint32(i)
	}

	invalidCounts := 0
	for i := 0; i < len(data); i++ {
		var account AccountInfo
		assets := make([]AccountAsset, 0, 8)
		account.TotalEquity = new(big.Int).SetInt64(0) // [unknown]
		account.TotalDebt = new(big.Int).SetInt64(0)   // [unknown]
		// first element of data[i] is ID. we use accountIndex instead
		account.AccountIndex = uint32(accountIndex)
		accountId := HashBytesForUID(data[i][1]) // uid to hashed id
		if len(accountId) != 32 {
			panic("accountId is invalid: " + data[i][1])
		}
		account.AccountId = new(fr.Element).SetBytes(accountId).Marshal()
		var tmpAsset AccountAsset

		multiplier := int64(100000000)
		for j := 0; j < AssetCounts; j++ {
			var balance int64
			var err error
			if AssetTypeForTwoDigits[cexAssetsInfo[j].Symbol] {
				balance, err = ConvertFloatStrToInt64(data[i][j+2], 100)
			} else {
				balance, err = ConvertFloatStrToInt64(data[i][j+2], multiplier)
			}

			if err != nil {
				//fmt.Println(cexAssetsInfo)
				fmt.Println("the symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account uid:", data[i][1], "balance data wrong:", err.Error())
				invalidCounts += 1
				continue
			}

			if balance != 0 {
				tmpAsset.Index = uint16(j)
				tmpAsset.Balance = balance
				assets = append(assets, tmpAsset)
			}
		}

		totalEquity, err := ConvertFloatStrToUint64(data[i][AssetCounts+2], multiplier)
		if err != nil {
			fmt.Println("account uid:", data[i][1], "TotalEquity data wrong:", err.Error())
			invalidCounts += 1
			continue
		}
		account.TotalEquity = new(big.Int).SetUint64(totalEquity)
		totalDebt, err := ConvertFloatStrToUint64(data[i][AssetCounts+2+1], multiplier)
		if err != nil {
			fmt.Println("account uid:", data[i][1], "TotalDebt data wrong:", err.Error())
			invalidCounts += 1
			continue
		}
		account.TotalDebt = new(big.Int).SetUint64(totalDebt)

		account.Assets = assets
		if account.TotalEquity.Cmp(account.TotalDebt) >= 0 {
			accounts[accountIndex] = account
			accountIndex += 1
		} else {
			invalidCounts += 1
			fmt.Println("account", data[i][1], "data wrong: total debt is bigger than equity:", account.TotalDebt, account.TotalEquity)
		}

		if i%100000 == 0 {
			runtime.GC()
		}
	}
	accounts = accounts[:accountIndex]
	fmt.Println("The invalid accounts number is ", invalidCounts)
	fmt.Println("The valid accounts number is ", len(accounts))
	return accounts, cexAssetsInfo, nil
}

func ConvertFloatStrToInt64(f string, multiplier int64) (int64, error) {
	if f == "0.0" {
		return 0, nil
	}
	numFloat, err := decimal.NewFromString(f)
	if err != nil {
		return 0, err
	}
	numFloat = numFloat.Mul(decimal.NewFromInt(multiplier))
	numBigInt := numFloat.BigInt()
	if !numBigInt.IsInt64() {
		return 0, errors.New("overflow uint64")
	}
	num := numBigInt.Int64()
	return num, nil
}

func ConvertFloatStrToUint64(f string, multiplier int64) (uint64, error) {
	if f == "0.0" {
		return 0, nil
	}
	numFloat, err := decimal.NewFromString(f)
	if err != nil {
		return 0, err
	}
	numFloat = numFloat.Mul(decimal.NewFromInt(multiplier))
	numBigInt := numFloat.BigInt()
	if !numBigInt.IsUint64() {
		return 0, errors.New("overflow uint64")
	}
	num := numBigInt.Uint64()
	return num, nil
}

func DecodeBatchWitness(data string) *BatchCreateUserWitness {
	var witnessForCircuit BatchCreateUserWitness
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Println("deserialize batch witness failed: ", err.Error())
		return nil
	}
	unserializeBuf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(unserializeBuf)
	err = dec.Decode(&witnessForCircuit)
	if err != nil {
		fmt.Println("unmarshal batch witness failed: ", err.Error())
		return nil
	}
	for i := 0; i < len(witnessForCircuit.CreateUserOps); i++ {
		userAssets := make([]AccountAsset, AssetCounts)
		storeUserAssets := witnessForCircuit.CreateUserOps[i].Assets
		for p := 0; p < len(storeUserAssets); p++ {
			userAssets[storeUserAssets[p].Index] = storeUserAssets[p]
		}
		witnessForCircuit.CreateUserOps[i].Assets = userAssets
	}
	return &witnessForCircuit
}

func AccountInfoToHash(account *AccountInfo, hasher *hash.Hash) []byte {
	assetCommitment := ComputeUserAssetsCommitment(hasher, account.Assets)
	(*hasher).Reset()
	// compute new account leaf node hash
	accountHash := poseidon.PoseidonBytes(account.AccountId, account.TotalEquity.Bytes(), account.TotalDebt.Bytes(), assetCommitment)
	return accountHash
}

func RecoverAfterCexAssets(witness *BatchCreateUserWitness) []CexAssetInfo {
	cexAssets := witness.BeforeCexAssets
	for i := 0; i < len(witness.CreateUserOps); i++ {
		for j := 0; j < len(witness.CreateUserOps[i].Assets); j++ {
			asset := &witness.CreateUserOps[i].Assets[j]
			cexAssets[asset.Index].TotalBalance = SafeAddInt64(cexAssets[asset.Index].TotalBalance, asset.Balance)
		}
	}
	// sanity check
	hasher := poseidon.NewPoseidon()
	for i := 0; i < len(cexAssets); i++ {
		commitment := ConvertAssetInfoToBytes(cexAssets[i])
		hasher.Write(commitment)
	}
	cexCommitment := hasher.Sum(nil)
	if string(cexCommitment) != string(witness.AfterCEXAssetsCommitment) {
		panic("after cex commitment verify failed")
	}
	return cexAssets
}

func RecoverAfterTotalCexAssets(witness *BatchCreateUserWitness) CexAssetsTotal {
	totalCexAssets := witness.TotalCexAssets
	return totalCexAssets
}

func ComputeCexAssetsCommitment(cexAssetsInfo []CexAssetInfo) []byte {
	hasher := poseidon.NewPoseidon()
	emptyCexAssets := make([]CexAssetInfo, AssetCounts-len(cexAssetsInfo))
	cexAssetsInfo = append(cexAssetsInfo, emptyCexAssets...)
	for i := 0; i < len(cexAssetsInfo); i++ {
		commitment := ConvertAssetInfoToBytes(cexAssetsInfo[i])
		hasher.Write(commitment)
	}
	return hasher.Sum(nil)
}
