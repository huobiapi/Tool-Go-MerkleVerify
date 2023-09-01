package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"merkleverifytool/merkle_groth16/src/utils"
	"merkleverifytool/merkle_groth16/src/witness/config"
	"merkleverifytool/merkle_groth16/src/witness/witness"
)

func main() {
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	flag.Parse()
	witnessConfig := &config.Config{} // witness/config/config.go
	content, err := ioutil.ReadFile("src/witness/config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, witnessConfig)
	if err != nil {
		panic(err.Error())
	}
	if *remotePasswdConfig != "" {
		s, err := utils.GetMysqlSource(witnessConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		witnessConfig.MysqlDataSource = s
	}
	accounts, cexAssetsInfo, err := utils.ParseUserDataSet(witnessConfig.UserDataFile)
	fmt.Println("account counts", len(accounts))
	if err != nil {
		panic(err.Error())
	}
	accountTree, err := utils.NewAccountTree(witnessConfig.TreeDB.Driver, witnessConfig.TreeDB.Option.Addr)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("account tree init height is ", accountTree.LatestVersion())
	fmt.Printf("account tree root is %x\n", accountTree.Root())
	witnessService := witness.NewWitness(accountTree, uint32(len(accounts)), accounts, cexAssetsInfo, witnessConfig)
	witnessService.Run()
	fmt.Println("witness service run finished...")
}
