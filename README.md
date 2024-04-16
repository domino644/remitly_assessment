# IAM::ROLE Verifier

## What does the code do?
1. Reads JSON file given path
2. Checks JSON validity - syntax, containment of required fields, values
3. Checks if any Resource contains "*"
   
## Covered edge cases
1. JSON is not syntactically valid
2. Wrong file path
3. Multiple Statements
4. Resource not being an array but an object
5. Action not being an array but an object
6. Invalid PolicyName
7. JSON without Sid
8. JSON without Resource


## Tests
1. Logic tests
2. Error handling tests

## Running program
### Requirements
`go 1.22.1`
### Instruction
Clone repository 
```
git clone https://github.com/domino644/remitly_assessment.git
```
Go to `iam_role_verifier` folder
```
cd iam_role_verifier
```
To execute program use
```
go run verifier.go
```
Then paste path to JSON file you want to check and hit enter
To test use
```
go test
```