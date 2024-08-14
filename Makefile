.PHONY: build-local



merkle_verify:
	go build -o build/MerkleVerify main/main.go

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