package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type RolePolicy struct {
	PolicyName     string         `json:"PolicyName"`
	PolicyDocument PolicyDocument `json:"PolicyDocument"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

func JSONValidator(path string) bool {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}
	var rolePolicy RolePolicy
	err = json.Unmarshal(byteValue, &rolePolicy)
	if err != nil {
		panic(err)
	}
	if len(rolePolicy.PolicyDocument.Statement) == 1 && rolePolicy.PolicyDocument.Statement[0].Resource == "*" {
		return false
	}
	return true
}

func main() {
	fmt.Println(JSONValidator("./json/test.json"))
}
