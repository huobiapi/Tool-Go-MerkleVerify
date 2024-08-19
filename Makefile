.PHONY: build-local



merkle_verify:
	go build -o build/MerkleVerify-macos-x64 main/main.go

merkle_verify_linux:
 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/MerkleVerify-linux-x64 main/main.go

merkle_verify_windows:
 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/MerkleVerify-win-x64.exe main/main.go

keygen:
	go build -o build/MerkleVerify merkle_groth16/src/keygen/main.go

prover:
	go build -o build/MerkleVerify merkle_groth16/src/prover/main.go

userproof:
	go build -o build/MerkleVerify merkle_groth16/src/userproof/main.go

verifier:
	go build -o build/MerkleVerify merkle_groth16/src/verifier/main.go

witness:
	go build -o build/MerkleVerify merkle_groth16/src/witness/main.go