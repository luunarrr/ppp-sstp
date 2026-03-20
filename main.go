package main

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type parsedArgs struct {
	Listen        string
	CertDir       string
	Endpoint      string
	MTU           int
	MSSClamp      *int // nil=auto, 0=off, >0=forced
	User          string
	Password      string
	ServerRouteIP string
	Ignored       []string
}

func parseArgs(args []string) parsedArgs {
	cfg := parsedArgs{
		Listen: "127.0.0.1:8443",
	}

	logLevel := ""
	for i := 0; i < len(args); i++ {
		key := args[i]
		if key == "-l" && i+1 < len(args) {
			logLevel = args[i+1]
			_ = logLevel
			i++
			continue
		}
		if i+1 < len(args) {
			val := args[i+1]
			switch key {
			case "listen":
				cfg.Listen = val
				i++
				continue
			case "cert-dir":
				cfg.CertDir = val
				i++
				continue
			case "endpoint":
				cfg.Endpoint = val
				i++
				continue
			case "mtu":
				n := 0
				for _, c := range val {
					if c >= '0' && c <= '9' {
						n = n*10 + int(c-'0')
					}
				}
				cfg.MTU = n
				i++
				continue
			case "user":
				cfg.User = val
				i++
				continue
			case "password":
				cfg.Password = val
				i++
				continue
			case "server-route":
				cfg.ServerRouteIP = val
				i++
				continue
			case "mss-clamp":
				n := 0
				for _, c := range val {
					if c >= '0' && c <= '9' {
						n = n*10 + int(c-'0')
					}
				}
				cfg.MSSClamp = &n
				i++
				continue
			}
		}
		cfg.Ignored = append(cfg.Ignored, key)
	}
	return cfg
}

func main() {
	logLevel := "info"
	for i, a := range os.Args[1:] {
		if a == "-l" && i+1 < len(os.Args[1:]) {
			logLevel = os.Args[i+2]
			break
		}
	}

	zapLevel := zapcore.InfoLevel
	switch strings.ToLower(logLevel) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	}

	zapCfg := zap.NewProductionConfig()
	zapCfg.Level.SetLevel(zapLevel)
	zapCfg.Encoding = "console"
	logger, err := zapCfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	l := logger.Named("sstp")

	cfg := parseArgs(os.Args[1:])

	if len(cfg.Ignored) > 0 {
		l.Warn("ignored unknown args", zap.Strings("args", cfg.Ignored))
	}

	if cfg.CertDir == "" {
		l.Fatal("cert-dir is required")
	}

	discLog := "none"
	if cfg.Endpoint != "" {
		discLog = cfg.Endpoint
	}
	l.Info("starting",
		zap.String("listen", cfg.Listen),
		zap.String("certDir", cfg.CertDir),
		zap.String("discriminator", discLog))

	if cfg.Endpoint == "" {
		bridge := &SSTPBridge{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Logger:        l,
			MTU:           cfg.MTU,
			MSSClamp:      cfg.MSSClamp,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := bridge.Run(); err != nil {
			l.Info("session ended", zap.Error(err))
		}
		return
	}

	master, ipcServer, err := TryBecomeMaster(cfg.Endpoint)
	if err != nil {
		l.Fatal("MLPPP IPC election failed", zap.Error(err))
	}

	if master {
		bridge := &SSTPBridge{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Logger:        l,
			Discriminator: cfg.Endpoint,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			MTU:           cfg.MTU,
			MSSClamp:      cfg.MSSClamp,
			IPCServer:     ipcServer,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := bridge.Run(); err != nil {
			l.Info("session ended", zap.Error(err))
		}
	} else {
		worker := &MLPPPWorker{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Discriminator: cfg.Endpoint,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			MTU:           cfg.MTU,
			Logger:        l,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := worker.Run(); err != nil {
			l.Info("MLPPP worker exited", zap.Error(err))
		}
	}
}
