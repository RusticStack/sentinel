package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func describe() string {
	srv := grpc.NewServer()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	logger := zap.NewNop()
	root := &cobra.Command{Use: "b05"}
	return fmt.Sprint(srv != nil, engine != nil, logger != nil, root.Use)
}

func main() { fmt.Println(describe()) }
