package main

import (
	"essence"
	"fmt"
)

func main() {
	id, _ := essence.UUIDv4Generate()
	fmt.Println(id.String())
}
