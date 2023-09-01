package witness

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"merkleverifytool/merkle_groth16/src/utils"
	"merkleverifytool/merkle_groth16/src/witness/config"

	bsmt "github.com/bnb-chain/zkbnb-smt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Witness struct {
	accountTree        bsmt.SparseMerkleTree
	totalOpsNumber     uint32
	witnessModel       WitnessModel
	ops                []utils.AccountInfo
	cexAssets          []utils.CexAssetInfo
	db                 *gorm.DB
	ch                 chan BatchWitness
	quit               chan int
	accountHashChan    [utils.BatchCreateUserOpsCounts]chan []byte
	currentBatchNumber int64
}

// NewWitness 创建 Witness 结构体
func NewWitness(accountTree bsmt.SparseMerkleTree, totalOpsNumber uint32,
	ops []utils.AccountInfo, cexAssets []utils.CexAssetInfo,
	config *config.Config) *Witness {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             60 * time.Second, // Slow SQL threshold
			LogLevel:                  logger.Silent,    // Log level
			IgnoreRecordNotFoundError: true,             // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,            // Disable color
		},
	)
	db, err := gorm.Open(mysql.Open(config.MysqlDataSource), &gorm.Config{
		Logger: newLogger,
	})
	fmt.Println("db=", db)
	if err != nil {
		panic(err.Error())
	}
	return &Witness{
		accountTree:        accountTree,
		totalOpsNumber:     totalOpsNumber,
		witnessModel:       NewWitnessModel(db, config.DbSuffix),
		ops:                ops,
		cexAssets:          cexAssets,
		ch:                 make(chan BatchWitness, 100),
		quit:               make(chan int, 1),
		currentBatchNumber: 0,
	}
}

func (w *Witness) Run() {
	// create table first
	w.witnessModel.CreateBatchWitnessTable()
	latestWitness, err := w.witnessModel.GetLatestBatchWitness()
	var height int64
	beforeTotalCexAssets := utils.CexAssetsTotal{
		BeforeCEXTotalEquity: 0,
		AfterCEXTotalEquity:  0,
		BeforeCEXTotalDebt:   0,
		AfterCEXTotalDebt:    0,
	}
	if err == utils.DbErrNotFound {
		height = -1 // 首次执行
	}
	if err != nil && err != utils.DbErrNotFound {
		panic(err.Error())
	}
	if err == nil {
		height = latestWitness.Height
		w.cexAssets, beforeTotalCexAssets = w.GetCexAssets(latestWitness)
	}

	batchNumber := (w.totalOpsNumber + utils.BatchCreateUserOpsCounts - 1) / utils.BatchCreateUserOpsCounts
	if height == int64(batchNumber)-1 {
		fmt.Println("already generate all accounts witness")
		return
	}
	w.currentBatchNumber = height
	fmt.Println("latest height is ", height)

	// tree version
	if w.accountTree.LatestVersion() > bsmt.Version(height+1) {
		rollbackVersion := bsmt.Version(height + 1)
		err = w.accountTree.Rollback(rollbackVersion)
		if err != nil {
			fmt.Println("rollback failed ", rollbackVersion, err.Error())
			panic("rollback failed")
		} else {
			fmt.Printf("rollback to %x\n", w.accountTree.Root())
		}
	} else if w.accountTree.LatestVersion() < bsmt.Version(height+1) {
		panic("account tree version is less than current height")
	} else {
		fmt.Println("normal starting...")
	}

	paddingAccountCounts := batchNumber*utils.BatchCreateUserOpsCounts - w.totalOpsNumber
	for i := uint32(0); i < paddingAccountCounts; i++ {
		emptyAccount := utils.AccountInfo{
			AccountIndex: i + w.totalOpsNumber,
			TotalEquity:  new(big.Int).SetInt64(0),
			TotalDebt:    new(big.Int).SetInt64(0),
			Assets:       make([]utils.AccountAsset, 0),
		}
		w.ops = append(w.ops, emptyAccount)
	}

	poseidonHasher := poseidon.NewPoseidon()
	go w.WriteBatchWitnessToDB()
	for i := 0; i < utils.BatchCreateUserOpsCounts; i++ {
		w.accountHashChan[i] = make(chan []byte, 1)
	}
	cpuCores := runtime.NumCPU()
	workersNum := 1
	if cpuCores > 2 {
		workersNum = cpuCores - 2
	}
	averageCount := int64(utils.BatchCreateUserOpsCounts/workersNum + 1)
	for i := int64(0); i < int64(workersNum); i++ {
		go func(index int64) {
			for j := height + 1; j < int64(batchNumber); j++ {
				if index*averageCount >= utils.BatchCreateUserOpsCounts {
					break
				}
				lowAccountIndex := index*averageCount + j*utils.BatchCreateUserOpsCounts
				highAccountIndex := averageCount + lowAccountIndex
				if highAccountIndex > (j+1)*utils.BatchCreateUserOpsCounts {
					highAccountIndex = (j + 1) * utils.BatchCreateUserOpsCounts
				}
				currentAccountIndex := j * utils.BatchCreateUserOpsCounts
				w.ComputeAccountHash(uint32(lowAccountIndex), uint32(highAccountIndex), uint32(currentAccountIndex))
			}
		}(i)
	}

	for i := height + 1; i < int64(batchNumber); i++ {
		totalCexAssets := utils.CexAssetsTotal{
			BeforeCEXTotalEquity: beforeTotalCexAssets.AfterCEXTotalEquity,
			AfterCEXTotalEquity:  0,
			BeforeCEXTotalDebt:   beforeTotalCexAssets.AfterCEXTotalDebt,
			AfterCEXTotalDebt:    0,
		}
		batchCreateUserWit := &utils.BatchCreateUserWitness{
			BeforeAccountTreeRoot: w.accountTree.Root(),
			BeforeCexAssets:       make([]utils.CexAssetInfo, utils.AssetCounts),
			CreateUserOps:         make([]utils.CreateUserOperation, utils.BatchCreateUserOpsCounts),
			TotalCexAssets:        totalCexAssets,
		}
		copy(batchCreateUserWit.BeforeCexAssets[:], w.cexAssets[:])
		for j := 0; j < len(w.cexAssets); j++ {
			commitment := utils.ConvertAssetInfoToBytes(w.cexAssets[j])
			poseidonHasher.Write(commitment)
		}
		batchCreateUserWit.BeforeCEXAssetsCommitment = poseidonHasher.Sum(nil)
		poseidonHasher.Reset()

		batchCreateUserWit.TotalCexAssets.AfterCEXTotalEquity = batchCreateUserWit.TotalCexAssets.BeforeCEXTotalEquity
		batchCreateUserWit.TotalCexAssets.AfterCEXTotalDebt = batchCreateUserWit.TotalCexAssets.BeforeCEXTotalDebt

		for j := i * utils.BatchCreateUserOpsCounts; j < (i+1)*utils.BatchCreateUserOpsCounts; j++ {
			w.ExecuteBatchCreateUser(uint32(j), uint32(i), batchCreateUserWit)
			index := uint32(j) - uint32(i)*utils.BatchCreateUserOpsCounts
			batchCreateUserWit.TotalCexAssets.AfterCEXTotalEquity = utils.SafeAdd(
				batchCreateUserWit.TotalCexAssets.AfterCEXTotalEquity, batchCreateUserWit.CreateUserOps[index].TotalEquity)
			batchCreateUserWit.TotalCexAssets.AfterCEXTotalDebt = utils.SafeAdd(
				batchCreateUserWit.TotalCexAssets.AfterCEXTotalDebt, batchCreateUserWit.CreateUserOps[index].TotalDebt)
		}
		for j := 0; j < len(w.cexAssets); j++ {
			commitment := utils.ConvertAssetInfoToBytes(w.cexAssets[j])
			poseidonHasher.Write(commitment)
		}
		batchCreateUserWit.AfterCEXAssetsCommitment = poseidonHasher.Sum(nil)
		poseidonHasher.Reset()
		batchCreateUserWit.AfterAccountTreeRoot = w.accountTree.Root()

		// compute batch commitment
		batchCreateUserWit.BatchCommitment = poseidon.PoseidonBytes(
			batchCreateUserWit.BeforeAccountTreeRoot,
			batchCreateUserWit.AfterAccountTreeRoot,
			batchCreateUserWit.BeforeCEXAssetsCommitment,
			batchCreateUserWit.AfterCEXAssetsCommitment)

		var serializeBuf bytes.Buffer
		enc := gob.NewEncoder(&serializeBuf)
		err := enc.Encode(batchCreateUserWit)
		if err != nil {
			panic(err.Error())
		}
		witness := BatchWitness{
			Height:      int64(i),
			WitnessData: base64.StdEncoding.EncodeToString(serializeBuf.Bytes()),
			Status:      StatusPublished,
		}
		accPrunedVersion := bsmt.Version(atomic.LoadInt64(&w.currentBatchNumber) + 1)
		ver, err := w.accountTree.Commit(&accPrunedVersion)
		if err != nil {
			fmt.Println("ver is ", ver)
			panic(err.Error())
		}
		w.ch <- witness
	}
	close(w.ch)
	<-w.quit
	fmt.Println("cex assets info is ", w.cexAssets)
	fmt.Printf("witness run finished, the account tree root is %x\n", w.accountTree.Root())
}

func (w *Witness) GetCexAssets(wit *BatchWitness) ([]utils.CexAssetInfo, utils.CexAssetsTotal) {
	witness := utils.DecodeBatchWitness(wit.WitnessData)
	if witness == nil {
		panic("decode invalid witness data")
	}
	cexAssetsInfo := utils.RecoverAfterCexAssets(witness)
	totalCexAssets := utils.RecoverAfterTotalCexAssets(witness)
	fmt.Println("recover cex assets successfully")
	return cexAssetsInfo, totalCexAssets
}

func (w *Witness) WriteBatchWitnessToDB() {
	datas := make([]BatchWitness, 1)
	for witness := range w.ch {
		datas[0] = witness
		err := w.witnessModel.CreateBatchWitness(datas)
		if err != nil {
			panic("create batch witness failed " + err.Error())
		}
		atomic.StoreInt64(&w.currentBatchNumber, witness.Height)
		if witness.Height%100 == 0 {
			fmt.Println("save batch ", witness.Height, " to db")
		}
	}
	w.quit <- 0
}

func (w *Witness) ComputeAccountHash(accountIndex uint32, highAccountIndex uint32, currentIndex uint32) {
	poseidonHasher := poseidon.NewPoseidon()
	for i := accountIndex; i < highAccountIndex; i++ {
		w.accountHashChan[i-currentIndex] <- utils.AccountInfoToHash(&w.ops[i], &poseidonHasher) // w.ops: AccountInfo
	}
}

func (w *Witness) ExecuteBatchCreateUser(accountIndex uint32, currentNumber uint32, batchCreateUserWit *utils.BatchCreateUserWitness) {
	index := accountIndex - currentNumber*utils.BatchCreateUserOpsCounts
	account := w.ops[accountIndex]
	batchCreateUserWit.CreateUserOps[index].BeforeAccountTreeRoot = w.accountTree.Root()
	accountProof, err := w.accountTree.GetProof(uint64(account.AccountIndex))
	if err != nil {
		panic(err.Error())
	}
	copy(batchCreateUserWit.CreateUserOps[index].AccountProof[:], accountProof[:])
	for p := 0; p < len(account.Assets); p++ {
		// update cexAssetInfo
		w.cexAssets[account.Assets[p].Index].TotalBalance = utils.SafeAddInt64(w.cexAssets[account.Assets[p].Index].TotalBalance, account.Assets[p].Balance)
	}
	// update account tree
	accountHash := <-w.accountHashChan[index]
	err = w.accountTree.Set(uint64(account.AccountIndex), accountHash)
	if err != nil {
		panic(err.Error())
	}
	batchCreateUserWit.CreateUserOps[index].AfterAccountTreeRoot = w.accountTree.Root()
	batchCreateUserWit.CreateUserOps[index].AccountIndex = account.AccountIndex
	batchCreateUserWit.CreateUserOps[index].AccountIdHash = account.AccountId
	batchCreateUserWit.CreateUserOps[index].Assets = account.Assets
	batchCreateUserWit.CreateUserOps[index].TotalEquity = account.TotalEquity.Uint64()
	batchCreateUserWit.CreateUserOps[index].TotalDebt = account.TotalDebt.Uint64()
}
