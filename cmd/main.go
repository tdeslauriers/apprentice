package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/manager"
	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler).
		With(slog.String(util.ServiceKey, util.ServiceApprentice)))

	// create a logger for the main package
	logger := slog.Default().
		With(slog.String(util.PackageKey, util.PackageMain)).
		With(slog.String(util.ComponentKey, util.ComponentMain))

	def := config.SvcDefinition{
		ServiceName: util.ServiceApprentice,
		Tls:         config.MutualTls,
		Requires: config.Requires{
			S2sClient:        true,
			Db:               true,
			IndexSecret:      true,
			AesSecret:        true,
			Identity:         true,
			S2sVerifyingKey:  true,
			UserVerifyingKey: true,
		},
	}

	// load the configuration values for service creation
	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("error loading %s task management service configuration", util.ServiceApprentice),
			"err", err.Error())
		os.Exit(1)
	}

	mgr, err := manager.New(config)
	if err != nil {
		logger.Error(fmt.Sprintf("error creating %s task management service", def.ServiceName),
			"err", err.Error())
		os.Exit(1)
	}

	defer mgr.CloseDb()

	if err := mgr.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s task management service", def.ServiceName),
			"err", err.Error())
		os.Exit(1)
	}

	select {}
}
