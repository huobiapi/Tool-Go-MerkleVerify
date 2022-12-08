package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"

	"merkleverifytool/merkle"
)

func main() {
	Execute()
}

var proofJsonFile string
var failStr = "Merkle proof verify failed! "

var rootCmd = &cobra.Command{
	Use:   "MerkleValidator",
	Short: "merkle tree path  validation",
	Long:  ``,
	Run:   MerkleVerify,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&proofJsonFile, "file", "", "")
}

func initConfig() {}

func MerkleVerify(cmd *cobra.Command, args []string) {
	log.Println("Merkle verify start")
	if proofJsonFile == "" {
		log.Println(failStr, "Invalid merkle proof file")
		return
	}
	buf, err := ioutil.ReadFile(proofJsonFile)
	if err != nil {
		log.Println(failStr, "Invalid merkle proof file", err)
		return
	}
	if len(buf) == 0 {
		log.Println(failStr, "Empty merkle proof file")
		return
	}
	pf := new(merkle.JsonProofPath)
	if err := json.Unmarshal(buf, &pf); err != nil {
		log.Println(fmt.Sprintf(failStr+"error:%s", err))
		return
	}

	verified, err := merkle.VerifyProofFile(pf)

	if verified {
		log.Println("Merkle proof verify passed.")
		return
	} else {
		if err != nil {
			log.Println(failStr + err.Error())
			return
		}
		log.Println(failStr)
	}
}
