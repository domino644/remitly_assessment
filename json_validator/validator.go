package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type RolePolicy struct {
	PolicyName     string         `json:"PolicyName"`
	PolicyDocument PolicyDocument `json:"PolicyDocument"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement interface{} `json:"Statement"`
}

type Statement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

func validatePolicyName(policyName string) (bool, error) {
	if len(policyName) < 1 || len(policyName) > 128 {
		return false, fmt.Errorf("PolicyName length has to be between 1 and 128 but is %v", len(policyName))
	}
	re := regexp.MustCompile(`[\w+=,.@-]+`)
	if !re.Match([]byte(policyName)) {
		return false, errors.New("PolicyName doesn't match wanted format")
	}
	return true, nil
}
func validateVersion(version string) (bool, error) {
	if version != "2012-10-17" && version != "2008-10-17" {
		return false, fmt.Errorf("accepted versions are: 2012-10-17 and 2008-10-17 but %s was given", version)
	}
	return true, nil
}

func validateEffect(effect string) (bool, error) {
	if effect != "Allow" && effect != "Deny" {
		return false, fmt.Errorf("accepted effects are: Allow and Deny but %s was given", effect)
	}
	return true, nil
}

func checkForAsterrisk(statements []Statement) (bool, error) {
	for _, stmt := range statements {
		if ok, err := validateEffect(stmt.Effect); !ok {
			return false, err
		}
		if stmt.Resource == "*" {
			return false, nil
		}
	}
	return true, nil
}

func readJSON(path string) []byte {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}
	return byteValue
}

func parseJSONToRolePolicy(byteValue []byte) (*RolePolicy, error) {
	var rolePolicy RolePolicy
	err := json.Unmarshal(byteValue, &rolePolicy)
	if err != nil {
		return nil, err
	}
	return &rolePolicy, nil
}

func validateJSON(byteValue []byte) (bool, error) {
	if !json.Valid(byteValue) {
		return false, errors.New("invalid JSON")
	}
	rolePolicy, err := parseJSONToRolePolicy(byteValue)
	if err != nil {
		return false, err
	}
	if ok, err := validatePolicyName(rolePolicy.PolicyName); !ok {
		return false, err
	}
	if ok, err := validateVersion(rolePolicy.PolicyDocument.Version); !ok {
		return false, err
	}
	return true, nil

}

func extractStatements(rolePolicy *RolePolicy) ([]Statement, error) {
	var statements []Statement
	switch stmt := rolePolicy.PolicyDocument.Statement.(type) {
	case []interface{}:
		for _, s := range stmt {
			tmp := s.(map[string]interface{})
			var statement Statement
			statement.Effect = tmp["Effect"].(string)
			statement.Resource = tmp["Resource"].(string)
			statement.Sid = tmp["Sid"].(string)
			if action, ok := tmp["Action"].([]interface{}); ok {
				for _, a := range action {
					statement.Action = append(statement.Action, a.(string))
				}
			}
			statements = append(statements, statement)
		}
		return statements, nil
	case map[string]interface{}:
		var statement Statement
		statement.Effect = stmt["Effect"].(string)
		statement.Resource = stmt["Resource"].(string)
		statement.Sid = stmt["Sid"].(string)
		if action, ok := stmt["Action"].([]interface{}); ok {
			for _, a := range action {
				statement.Action = append(statement.Action, a.(string))
			}
		}
		statements = append(statements, statement)
		return statements, nil
	default:
		return nil, fmt.Errorf("statements has to be either type of array or object but is %s", stmt)
	}
}

func Validate(path string) bool {
	byteValue := readJSON(path)
	if ok, err := validateJSON(byteValue); !ok {
		panic(err)
	}
	rolePolicy, err := parseJSONToRolePolicy(byteValue)
	if err != nil {
		panic(err)
	}
	statements, err := extractStatements(rolePolicy)
	if err != nil {
		panic(err)
	}
	output, err := checkForAsterrisk(statements)
	if err != nil {
		panic(err)
	}
	return output
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please provide path to JSON file to check: ")
	line, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	line = strings.TrimSpace(line)
	fmt.Println(Validate(line))
}
