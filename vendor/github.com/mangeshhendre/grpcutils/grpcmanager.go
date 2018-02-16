package grpcutils

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/kelseyhightower/envconfig"
	logxi "github.com/mgutz/logxi/v1"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
)

// GRPCManager is the struct which holds all the indirection around setting up a grpc service.
type GRPCManager struct {
	logger     logxi.Logger
	grpcServer *grpc.Server
	listen     net.Listener
	httpServer *http.Server
	myLife     time.Duration
}

type ManagerConfig struct {
	MinLife      int64  `split_words:"true" default:"3600" desc:"Minimum lifetime of the worker"`
	LifeRange    int64  `split_words:"true" default:"1800" desc:"Random range which will be added to the minimum life"`
	BindAddress  string `split_words:"true" default:"0.0.0.0" desc:"Address to bind to to serve up GRPC requests"`
	BindPort     string `split_words:"true" default:"8443" desc:"Port to bind to to serve up GRPC requests"`
	JWTCertPath  string `envconfig:"JWT_CERT_PATH" default:"/jwt_certs" desc:"Path to the directory containing authorized JWT certificates, named as ISSUER.pem"`
	SSLCertPath  string `envconfig:"SSL_CERT_PATH" default:"/certs/server.crt" desc:"Where to find the SSL Certificate"`
	SSLKeyPath   string `envconfig:"SSL_KEY_PATH" default:"/certs/server.key" desc:"Where to find the SSL Key"`
	DebugAddress string `split_words:"true" default:"0.0.0.0" desc:"Address to bind the http debug server to"`
	DebugPort    string `split_words:"true" default:"7777" desc:"Port to bind the http debug server to"`
}

const config_prefix string = "grpc"

// New creates a new GRPCManager
func New(name string) (*GRPCManager, error) {

	// Create a logger.
	logger := logxi.New(name)

	// Create a config storage location.
	c := &ManagerConfig{}

	envconfig.Usage(config_prefix, c)

	// Retrieve my config.
	err := envconfig.Process(config_prefix, c)
	if err != nil {
		logger.Fatal("Unable to get config", "Error", errors.Wrap(err, "Initializing configuration"))
	}

	logger.Debug("Configuration Data", "ManagerConfig", c)

	// Make us a new random seed.
	rand.Seed(time.Now().UnixNano())

	// Establish life range.
	myLife := time.Duration(c.MinLife+rand.Int63n(c.LifeRange)) * time.Second

	// Determine ports.
	httpServer := &http.Server{
		Addr: net.JoinHostPort(c.DebugAddress, c.DebugPort),
	}

	grpcServer, listen, err := MakeGRPCServer(
		logger,
		c.JWTCertPath,
		c.SSLCertPath,
		c.SSLKeyPath,
		c.BindAddress,
		c.BindPort,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create GRPC Server")
	}

	// Setup so that http debug will work.  Control security here by what hosts can get to the port.
	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) { return true, true }

	mgr := &GRPCManager{
		logger:     logger,
		grpcServer: grpcServer,
		listen:     listen,
		httpServer: httpServer,
		myLife:     myLife,
	}

	return mgr, nil
}

// RegisterHandlers takes care of registering all the relevant handlers.
func (m *GRPCManager) RegisterHandlers(handlers ...GRPCService) error {
	for _, v := range handlers {
		v.RegisterServices(m.grpcServer)
	}
	return nil
}

// WaitAWhile will pause for a bit to allow services to do their job.
func (m *GRPCManager) WaitAWhile() {
	m.logger.Info(fmt.Sprintf("Sleeping for %d Seconds", m.myLife/time.Second))

	time.Sleep(m.myLife)

	m.logger.Info(fmt.Sprintf("Done sleeping for %d Seconds", m.myLife/time.Second))
}

// ShutdownGracefully attempts to shutdown both a GRPC server and a httpServer in the most graceful fashion possible.
func (m *GRPCManager) ShutdownGracefully() {
	m.logger.Info("Shutting down GRPC")
	m.grpcServer.GracefulStop()
	m.logger.Info("Shut down GRPC")
	m.logger.Info("Shutting down http server")
	err := m.httpServer.Shutdown(context.TODO())
	if err != nil {
		m.logger.Info(fmt.Sprintf("Error shutting down httpserver: %v", err))
	}
	m.logger.Info("Shut down http server")
	m.logger.Info("Shutdown Complete")
}

// Run Wraps starting, waiting, and shutting down.
func (m *GRPCManager) Run() {
	m.Startup()
	m.WaitAWhile()
	m.ShutdownGracefully()
}

// Startup is a convenience function which starts up the GRPC server and the HTTP Debug server.
func (m *GRPCManager) Startup() {
	m.StartupGRPC()
	m.StartupHTTPDebug()
}

// StartupGRPC starts up the grpc server in a goroutine so as not to block the main program flow.
func (m *GRPCManager) StartupGRPC() {
	go func() {
		m.logger.Info("GRPC Server starting up")
		m.logger.Info("GRPC Server stopped", "Result", m.grpcServer.Serve(m.listen))
	}()
}

// StartupHTTPDebug starts up the http debug server in a goroutine so as not to block the main program flow.
func (m *GRPCManager) StartupHTTPDebug() {
	go func() {
		m.logger.Info("Starting up debug http server")
		m.logger.Info("Server Stopped", "Result", m.httpServer.ListenAndServe())
	}()
}
