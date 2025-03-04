package manager

import (
	"apprentice/internal/util"
	"apprentice/pkg/allowances"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/sign"
)

// Manager is the interface for the engine that runs this service
type Manager interface {
	// Run runs the task/allowance service
	Run() error
	CloseDb() error
}

// New creates a new Manager interface, returning a pointer to the concrete implementation
func New(config *config.Config) (Manager, error) {

	// server
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
		CaFiles:  []string{*config.Certs.ServerCa},
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure %s task management service server tls: %v", config.ServiceName, err)
	}

	// db client
	dbClientPki := &connect.Pki{
		CertFile: *config.Certs.DbClientCert,
		KeyFile:  *config.Certs.DbClientKey,
		CaFiles:  []string{*config.Certs.DbCaCert},
	}

	dbClientConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure database client tls: %v", err)
	}

	// db config
	dbUrl := data.DbUrl{
		Name:     config.Database.Name,
		Addr:     config.Database.Url,
		Username: config.Database.Username,
		Password: config.Database.Password,
	}

	db, err := data.NewSqlDbConnector(dbUrl, dbClientConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	repository := data.NewSqlRepository(db)

	// indexer
	hmacSecret, err := base64.StdEncoding.DecodeString(config.Database.IndexSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hmac secret: %v", err)
	}

	indexer := data.NewIndexer(hmacSecret)

	// field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption secret: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s jwt verifing key
	s2sPublicKey, err := sign.ParsePublicEcdsaCert(config.Jwt.S2sVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse s2s jwt verifying key: %v", err)
	}

	// jwt iamVerifier
	iamPublicKey, err := sign.ParsePublicEcdsaCert(config.Jwt.UserVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iam verifying public key: %v", err)
	}

	// service(s):
	allowance := allowances.NewService(repository, indexer, cryptor)

	// caller(s)
	identity := connect.NewS2sCaller(util.ServiceIdentity)

	return &manager{
		config:      *config,
		serverTls:   serverTlsConfig,
		repository:  repository,
		s2sVerifier: jwt.NewVerifier(config.ServiceName, s2sPublicKey),
		iamVerifier: jwt.NewVerifier(config.ServiceName, iamPublicKey),
		allowance:   allowance,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageManager)).
			With(slog.String(util.ComponentKey, util.ComponentManager)),
	}, nil
}

var _ Manager = (*manager)(nil)

// manager is the concrete implementation of the Manager interface
type manager struct {
	config      config.Config
	serverTls   *tls.Config
	repository  data.SqlRepository
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier
	allowance   allowances.Service
	identity   connect.S2sCaller

	logger *slog.Logger
}

func (m *manager) CloseDb() error {
	if err := m.repository.Close(); err != nil {
		m.logger.Error(fmt.Sprintf("error closing database: %v", err))
	}
	return nil
}

func (m *manager) Run() error {

	// allowances
	allowance := allowances.NewHandler(m.allowance, m.s2sVerifier, m.iamVerifier)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	managerServer := &connect.TlsServer{
		Addr:      m.config.ServicePort,
		Mux:       mux,
		TlsConfig: m.serverTls,
	}

	go func() {

		m.logger.Info(fmt.Sprintf("starting %s task management service on port %s", m.config.ServiceName, managerServer.Addr[1:]))
		if err := managerServer.Initialize(); err != http.ErrServerClosed {
			m.logger.Error(fmt.Sprintf("failed to start %s task management service: %v", m.config.ServiceName, err))
		}
	}()

	return nil
}
