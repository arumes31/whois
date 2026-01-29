package utils

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger

func InitLogger() {
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var err error
	Log, err = config.Build()
	if err != nil {
		panic(err)
	}
}

func Field(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}

func TestInitLogger() {
	Log = zap.NewNop()
}
