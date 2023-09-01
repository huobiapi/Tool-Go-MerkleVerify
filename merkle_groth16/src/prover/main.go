package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"merkleverifytool/merkle_groth16/src/prover/config"
	"merkleverifytool/merkle_groth16/src/prover/prover"
	"merkleverifytool/merkle_groth16/src/utils"
)

func main() {
	proverConfig := &config.Config{}
	content, err := ioutil.ReadFile("src/prover/config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, proverConfig)
	if err != nil {
		panic(err.Error())
	}
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	rerun := flag.Bool("rerun", false, "flag which indicates rerun proof generation")
	flag.Parse()
	if *remotePasswdConfig != "" {
		s, err := utils.GetMysqlSource(proverConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		proverConfig.MysqlDataSource = s
	}
	prover := prover.NewProver(proverConfig)
	prover.Run(*rerun)
}
