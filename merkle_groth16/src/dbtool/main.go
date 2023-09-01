package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"merkleverifytool/merkle_groth16/src/dbtool/config"
	"merkleverifytool/merkle_groth16/src/prover/prover"
	"merkleverifytool/merkle_groth16/src/userproof/model"
	"merkleverifytool/merkle_groth16/src/utils"
	"merkleverifytool/merkle_groth16/src/witness/witness"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	dbtoolConfig := &config.Config{}
	content, err := ioutil.ReadFile("src/dbtool/config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, dbtoolConfig)
	if err != nil {
		panic(err.Error())
	}

	onlyFlushKvrocks := flag.Bool("only_delete_kvrocks", false, "only delete kvrocks")
	deleteAllData := flag.Bool("delete_all", false, "delete kvrocks and mysql data")
	checkProverStatus := flag.Bool("check_prover_status", false, "check prover status")
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	queryCexAssetsConfig := flag.Bool("query_cex_assets", true, "query cex assets info")

	flag.Parse()

	if *remotePasswdConfig != "" {
		s, err := utils.GetMysqlSource(dbtoolConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		dbtoolConfig.MysqlDataSource = s
	}
	if *deleteAllData {
		db, err := gorm.Open(mysql.Open(dbtoolConfig.MysqlDataSource))
		if err != nil {
			panic(err.Error())
		}
		witnessModel := witness.NewWitnessModel(db, dbtoolConfig.DbSuffix)
		err = witnessModel.DropBatchWitnessTable()
		if err != nil {
			fmt.Println("drop witness table failed")
			panic(err.Error())
		}
		fmt.Println("drop witness table successfully")

		proofModel := prover.NewProofModel(db, dbtoolConfig.DbSuffix)
		err = proofModel.DropProofTable()
		if err != nil {
			fmt.Println("drop proof table failed")
			panic(err.Error())
		}
		fmt.Println("drop proof table successfully")

		userProofModel := model.NewUserProofModel(db, dbtoolConfig.DbSuffix)
		err = userProofModel.DropUserProofTable()
		if err != nil {
			fmt.Println("drop userproof table failed")
			panic(err.Error())
		}
		fmt.Println("drop userproof table successfully")
	}

	if *deleteAllData || *onlyFlushKvrocks {
		client := redis.NewClient(&redis.Options{
			Addr:            dbtoolConfig.TreeDB.Option.Addr,
			PoolSize:        500,
			MaxRetries:      5,
			MinRetryBackoff: 8 * time.Millisecond,
			MaxRetryBackoff: 512 * time.Millisecond,
			DialTimeout:     10 * time.Second,
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			PoolTimeout:     15 * time.Second,
			IdleTimeout:     5 * time.Minute,
		})
		client.FlushAll(context.Background())
		fmt.Println("kvrocks data drop successfully")
	}

	if *checkProverStatus {
		newLogger := logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold:             60 * time.Second, // Slow SQL threshold
				LogLevel:                  logger.Silent,    // Log level
				IgnoreRecordNotFoundError: true,             // Ignore ErrRecordNotFound error for logger
				Colorful:                  false,            // Disable color
			},
		)
		db, err := gorm.Open(mysql.Open(dbtoolConfig.MysqlDataSource), &gorm.Config{
			Logger: newLogger,
		})
		if err != nil {
			panic(err.Error())
		}
		witnessModel := witness.NewWitnessModel(db, dbtoolConfig.DbSuffix)
		proofModel := prover.NewProofModel(db, dbtoolConfig.DbSuffix)

		witnessCounts, err := witnessModel.GetRowCounts()
		if err != nil {
			panic(err.Error())
		}
		proofCounts, err := proofModel.GetRowCounts()
		fmt.Printf("Total witness item %d, Published item %d, Pending item %d, Finished item %d\n", witnessCounts[0], witnessCounts[1], witnessCounts[2], witnessCounts[3])
		fmt.Println(witnessCounts[0] - proofCounts)
	}

	if *queryCexAssetsConfig {
		db, err := gorm.Open(mysql.Open(dbtoolConfig.MysqlDataSource))
		if err != nil {
			panic(err.Error())
		}
		witnessModel := witness.NewWitnessModel(db, dbtoolConfig.DbSuffix)
		latestWitness, err := witnessModel.GetLatestBatchWitness()
		if err != nil {
			panic(err.Error())
		}
		witness := utils.DecodeBatchWitness(latestWitness.WitnessData)
		if witness == nil {
			panic("decode invalid witness data")
		}
		cexAssetsInfo := utils.RecoverAfterCexAssets(witness)
		var newAssetsInfo []utils.CexAssetInfo
		for i := 0; i < len(cexAssetsInfo); i++ {
			newAssetsInfo = append(newAssetsInfo, cexAssetsInfo[i])
		}
		cexAssetsInfoBytes, _ := json.MarshalIndent(newAssetsInfo, "", "  ")
		fmt.Println(string(cexAssetsInfoBytes))
		var new_resutls []map[string]interface{}
		err = json.Unmarshal(cexAssetsInfoBytes, &new_resutls)
		content, _ = ioutil.ReadFile("src/verifier/config/config.json")
		var results map[string]interface{}
		err = json.Unmarshal(content, &results)
		resulttable := results["ProofTable"]
		resultZkname := results["ZkKeyName"]
		results["ProofTable"] = resulttable
		results["ZkKeyName"] = resultZkname
		results["CexAssetsInfo"] = new_resutls
		bytevalue, err := json.Marshal(results)

		err = ioutil.WriteFile("src/verifier/config/config.json", bytevalue, 0644)

	}
}
