package manager

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/allowances"
	"github.com/tdeslauriers/apprentice/pkg/permissions"
	"github.com/tdeslauriers/apprentice/pkg/remittance"
	"github.com/tdeslauriers/apprentice/pkg/tasks"
	"github.com/tdeslauriers/apprentice/pkg/templates"
	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/sign"
)

// Manager is the interface for the engine that runs this service
type Manager interface {
	// Run runs the task/allowance service
	Run() error

	// CloseDb closes the database connection
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

	// allowance/tasks service client
	clientPki := &connect.Pki{
		CertFile: *config.Certs.ClientCert,
		KeyFile:  *config.Certs.ClientKey,
		CaFiles:  []string{*config.Certs.ClientCa},
	}

	clientConfig := connect.NewTlsClientConfig(clientPki)
	client, err := connect.NewTlsClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure s2s client config: %v", err)
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

	// caller(s):
	// retry config for s2s callers
	retry := connect.RetryConfiguration{
		MaxRetries:  5,
		BaseBackoff: 100 * time.Microsecond,
		MaxBackoff:  10 * time.Second,
	}

	s2s := connect.NewS2sCaller(config.ServiceAuth.Url, util.ServiceS2s, client, retry)
	identity := connect.NewS2sCaller(config.UserAuth.Url, util.ServiceIdentity, client, retry)

	// s2s token provider
	s2sCreds := provider.S2sCredentials{
		ClientId:     config.ServiceAuth.ClientId,
		ClientSecret: config.ServiceAuth.ClientSecret,
	}

	s2sTokenProvider := provider.NewS2sTokenProvider(s2s, s2sCreds, repository, cryptor)

	return &manager{
		config:           *config,
		serverTls:        serverTlsConfig,
		repository:       repository,
		s2sTokenProvider: s2sTokenProvider,
		s2sVerifier:      jwt.NewVerifier(config.ServiceName, s2sPublicKey),
		iamVerifier:      jwt.NewVerifier(config.ServiceName, iamPublicKey),
		identity:         identity,
		allowance:        allowances.NewService(db, indexer, cryptor),
		remittance:       remittance.NewService(db, indexer, cryptor, s2sTokenProvider, identity),
		template:         templates.NewService(db, cryptor),
		task:             tasks.NewService(db, indexer, cryptor),
		permissions:      permissions.NewService(db, indexer, cryptor),
		cleanup:          schedule.NewCleanup(db),

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageManager)).
			With(slog.String(util.ComponentKey, util.ComponentManager)),
	}, nil
}

var _ Manager = (*manager)(nil)

// manager is the concrete implementation of the Manager interface
type manager struct {
	config           config.Config
	serverTls        *tls.Config
	repository       data.SqlRepository
	s2sTokenProvider provider.S2sTokenProvider
	s2sVerifier      jwt.Verifier
	iamVerifier      jwt.Verifier
	identity         *connect.S2sCaller
	allowance        allowances.Service
	remittance       remittance.Service
	template         templates.Service
	task             tasks.Service
	permissions      permissions.Service
	cleanup          schedule.Cleanup

	logger *slog.Logger
}

func (m *manager) CloseDb() error {
	if err := m.repository.Close(); err != nil {
		m.logger.Error(fmt.Sprintf("error closing database: %v", err))
	}
	return nil
}

func (m *manager) Run() error {

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	// allowances
	allowance := allowances.NewHandler(m.allowance, m.permissions, m.s2sVerifier, m.iamVerifier, m.s2sTokenProvider, m.identity)
	mux.HandleFunc("/account", allowance.HandleAccount)
	mux.HandleFunc("/allowances/{slug...}", allowance.HandleAllowances)
	mux.HandleFunc("/allowances/permissions", allowance.HandlePermissions)

	// templates
	template := templates.NewHandler(m.template, m.allowance, m.task, m.s2sVerifier, m.iamVerifier, m.s2sTokenProvider, m.identity)
	mux.HandleFunc("/templates/{slug...}", template.HandleTemplates)

	// tasks
	task := tasks.NewHandler(m.task, m.allowance, m.permissions, m.s2sVerifier, m.iamVerifier, m.s2sTokenProvider, m.identity)
	mux.HandleFunc("/tasks", task.HandleTasks)

	// permissions
	permission := permissions.NewHandler(m.permissions, m.s2sVerifier, m.iamVerifier)
	mux.HandleFunc("/permissions/{slug...}", permission.HandlePermissions)

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

	// cleanup expired s2s tokens
	m.cleanup.ExpiredS2s()

	// generate scheduled tasks
	m.task.CreateDailyTasks()
	m.task.CreateWeeklyTasks()

	// conduct remittance disbursement
	m.remittance.Disburse()

	return nil
}
