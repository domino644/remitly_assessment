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
	PolicyName     string         `json:"PolicyName"`     //required
	PolicyDocument PolicyDocument `json:"PolicyDocument"` //required
}

type PolicyDocument struct {
	Version   string      `json:"Version"`   //required
	Statement interface{} `json:"Statement"` //required
}

type Statement struct {
	Sid      string      `json:"Sid"`
	Effect   string      `json:"Effect"` //required
	Action   interface{} `json:"Action"` //required
	Resource interface{} `json:"Resource"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please provide path to JSON file to check: ")
	line, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	line = strings.TrimSpace(line)
	output, err := Verify(line)
	if err != nil {
		panic(err)
	}
	fmt.Println(output)
}

func Verify(path string) (bool, error) {
	byteValue := mustReadJSON(path)
	if ok, err := validateJSON(byteValue); !ok {
		return false, err
	}
	rolePolicy, err := parseJSONToRolePolicy(byteValue)
	if err != nil {
		return false, err
	}
	statements, err := extractStatements(rolePolicy)
	if err != nil {
		return false, err
	}
	return checkForAsterrisk(statements), nil
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

func extractResources(resourcesRaw interface{}) ([]string, error) {
	var output []string
	switch res := resourcesRaw.(type) {
	case []interface{}:
		for _, r := range res {
			t, ok := r.(string)
			if !ok {
				return nil, fmt.Errorf("values of Resource has to be type of string but are %s", t)
			}
			output = append(output, t)
		}
	case string:
		output = append(output, res)
	default:
		return nil, fmt.Errorf("resource has to be either string or array of string but is %s", res)
	}
	return output, nil
}

func extractActions(actionsRaw interface{}) ([]string, error) {
	//if Actions are not given empty array is assigned
	if actionsRaw == nil {
		return []string{}, nil
	}
	var output []string
	switch act := actionsRaw.(type) {
	case []interface{}:
		for _, a := range act {
			t, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("values of Action has to be type of string but are %s", t)
			}
			output = append(output, t)
		}
	case string:
		output = append(output, act)
	default:
		return nil, fmt.Errorf("action has to be either string or array of string but is %s", act)
	}
	return output, nil
}

func extractStatements(rolePolicy *RolePolicy) ([]Statement, error) {
	var statements []Statement
	switch stmt := rolePolicy.PolicyDocument.Statement.(type) {
	case []interface{}:
		for _, s := range stmt {
			tmp := s.(map[string]interface{})
			var statement Statement
			e, ok := tmp["Effect"].(string)
			if !ok {
				return nil, fmt.Errorf("value Effect has to be string but is %v", tmp["Effect"])
			}
			statement.Effect = e

			//Resource is not required
			res, err := extractResources(tmp["Resource"])
			if err != nil {
				return nil, err
			}
			statement.Resource = res

			//Sid is not required
			s, ok := tmp["Sid"].(string)
			if !ok {
				if tmp["Sid"] != nil {
					return nil, fmt.Errorf("value Sid has to be string but is %v", tmp["Sid"])
				}
				//if Sid is not given empty string is assigned
				s = ""
			}
			statement.Sid = s

			act, err := extractActions(tmp["Action"])
			if err != nil {
				return nil, err
			}
			statement.Action = act
			statements = append(statements, statement)
		}
	case map[string]interface{}:
		var statement Statement

		e, ok := stmt["Effect"].(string)
		if !ok {
			return nil, fmt.Errorf("value Effect has to be string but is %v", stmt["Effect"])
		}
		statement.Effect = e

		//Resource is not required
		res, err := extractResources(stmt["Resource"])
		if err != nil {
			return nil, err
		}
		statement.Resource = res

		//Sid is not required
		s, ok := stmt["Sid"].(string)
		if !ok {
			if stmt["Sid"] != nil {
				return nil, fmt.Errorf("value Sid has to be string but is %v", stmt["Sid"])
			}
			//if Sid is not given empty string is assigned
			s = ""
		}
		statement.Sid = s

		act, err := extractActions(stmt["Action"])
		if err != nil {
			return nil, err
		}
		statement.Action = act
		statements = append(statements, statement)
	default:
		return nil, fmt.Errorf("statements has to be either type of array or object but is %s", stmt)
	}
	for _, stmt := range statements {
		if ok, err := validateEffect(stmt.Effect); !ok {
			return nil, err
		}
	}
	return statements, nil
}

func checkForAsterrisk(statements []Statement) bool {
	for _, stmt := range statements {
		for _, res := range stmt.Resource.([]string) {
			if res == "*" {
				return false
			}
		}
	}
	return true
}

func mustReadJSON(path string) []byte {
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

func validatePolicyName(policyName string) (bool, error) {
	if len(policyName) < 1 || len(policyName) > 128 {
		return false, fmt.Errorf("PolicyName length has to be between 1 and 128 but is %v", len(policyName))
	}
	re := regexp.MustCompile(`[\w+=,.@-]+`)
	if !re.Match([]byte(policyName)) {
		return false, errors.New("PolicyName doesn't match wanted format: `[\\w+=,.@-]+`")
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
