package grpcutils

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/mangeshhendre/grpcjwt"
	"github.com/mangeshhendre/jwtauthfunc"
	"github.com/mangeshhendre/jwtclient"
	logxi "github.com/mgutz/logxi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var codeToStatus = map[codes.Code]int{
	codes.OK:                 http.StatusOK,
	codes.Canceled:           http.StatusRequestTimeout,
	codes.Unknown:            http.StatusInternalServerError,
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.DeadlineExceeded:   http.StatusRequestTimeout,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.Unauthenticated:    http.StatusUnauthorized,
	codes.ResourceExhausted:  http.StatusForbidden,
	codes.FailedPrecondition: http.StatusPreconditionFailed,
	codes.Aborted:            http.StatusConflict,
	codes.OutOfRange:         http.StatusBadRequest,
	codes.Unimplemented:      http.StatusNotImplemented,
	codes.Internal:           http.StatusInternalServerError,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.DataLoss:           http.StatusInternalServerError,
}

// GRPCService provide the interface that lets us make and register in one step.
type GRPCService interface {
	RegisterServices(shim *grpc.Server)
}

// HTTPStatusFromCode converts a gRPC error code into the corresponding HTTP response status.
func HTTPStatusFromCode(code codes.Code) int {

	statusCode, ok := codeToStatus[code]
	if !ok {
		return http.StatusInternalServerError
	}
	return statusCode
}

// MakeGRPCClientConn is used to enforce a standard of injectors for client connections.
func MakeGRPCClientConn(logger logxi.Logger, authenticationURL, grpcUsername, grpcPassword, grpcHost, grpcPort string, insecure bool) (*grpc.ClientConn, error) {

	// Make a jwt client.
	jwtClientConfig := jwtclient.Config{
		AuthKey:    grpcUsername,
		AuthSecret: grpcPassword,
		URL:        authenticationURL,
		Insecure:   insecure,
	}

	// Setup a jwtclient
	jc, err := jwtclient.New(&jwtClientConfig)
	if err != nil {
		return nil, logger.Error("Unable to create jwtclient", "Error", err)
	}

	// Create a PerRPCCredentials receiver.
	creds, err := grpcjwt.NewFromClient(jc)
	if err != nil {
		return nil, logger.Error("Unable to create credentials", "Error", err)
	}

	// Transport credentials
	transportCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: insecure})

	hostToDial := net.JoinHostPort(
		grpcHost,
		grpcPort,
	)

	logger.Debug("Verifying Host To Dial", "Full String", hostToDial)

	conn, err := grpc.Dial(
		hostToDial,
		grpc.WithPerRPCCredentials(creds),
		grpc.WithTransportCredentials(transportCreds),
		//grpc.WithBlock(),
	)
	if err != nil {
		return nil, logger.Error("Unable to dial", "Error", err)
	}

	return conn, nil

}

// MakeGRPCServer attempts to setup the GRPC server according to the safeguardproperties standard methodology.
func MakeGRPCServer(logger logxi.Logger, jwtDir, certPath, keyPath, address, port string) (*grpc.Server, net.Listener, error) {
	// First make a parser
	// This means that we will ONLY accept rsa 256bit signatures.
	parser := jwt.Parser{ValidMethods: []string{"RS256"}}

	// Second we need a keyfunc.
	keyFunc, err := jwtclient.KeyFuncFromCertDir(jwtDir)
	if err != nil {
		return nil, nil, logger.Error("Unable to create keyfunc", "Error", err)
	}

	// Third make an authorizer  its job is to authorize the incoming request.
	// It needs to know where to find the keys that it will allow.
	authorizer, err := jwtauthfunc.New(&parser, keyFunc)
	if err != nil {
		return nil, nil, logger.Error("Unable to create authorizer", "Error", err)
	}

	// Fourth we establish a port to listen on.
	listen, err := net.Listen("tcp", net.JoinHostPort(address, port))
	if err != nil {
		return nil, nil, logger.Error("Unable to create listener", "Address", address, "Port", port, "Error", err)
	}

	// Fifth we create our serving credentials.
	tlsCreds, err := credentials.NewServerTLSFromFile(certPath, keyPath)
	if err != nil {
		return nil, nil, logger.Error("Unable to create tls server credentials", "certPath", certPath, "keyPath", keyPath, "Error", err)
	}

	// Sixth we create our grpc server instance.
	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(authorizer.Authorize)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authorizer.Authorize)),
		grpc.Creds(tlsCreds),
	)

	// 	Seventh we register a reflection instance.
	reflection.Register(grpcServer)

	// Now we return.
	return grpcServer, listen, nil

}

// EnvOrDefault will return the string value for a given key.
func EnvOrDefault(key, defaultValue string) string {
	return EnvOrDefaultAsString(key, defaultValue)
}

// EnvOrDefaultAsString will return the string value for a given key.
func EnvOrDefaultAsString(key, defaultValue string) string {
	result := os.Getenv(key)
	if len(result) == 0 {
		return logDecisionString(key, true, defaultValue)
	}
	return logDecisionString(key, false, result)
}

// EnvOrDefaultAsBool will return the bool value for a given key/default.
func EnvOrDefaultAsBool(key string, defaultValue bool) bool {
	result := os.Getenv(key)
	if len(result) == 0 {
		return logDecisionBool(key, true, defaultValue)
	}

	result = strings.ToLower(result)

	switch result {
	case "1", "true":
		return logDecisionBool(key, false, true)
	default:
		return logDecisionBool(key, false, false)
	}
}

// EnvOrDefaultAsInt64 will return the int64 value for a given key/default.
func EnvOrDefaultAsInt64(key string, defaultValue int64) int64 {
	result := os.Getenv(key)
	if len(result) == 0 {
		return logDecisionInt64(key, true, defaultValue)
	}

	val, err := strconv.ParseInt(result, 10, 64)
	if err != nil {
		return logDecisionInt64(key, true, defaultValue)
	}
	return logDecisionInt64(key, false, val)
}

// EnvOrDefaultAsInt32 will return the int32 value for a given key/default.
func EnvOrDefaultAsInt32(key string, defaultValue int32) int32 {
	result := os.Getenv(key)
	if len(result) == 0 {
		return logDecisionInt32(key, true, defaultValue)
	}

	val, err := strconv.ParseInt(result, 10, 32)
	if err != nil {
		return logDecisionInt32(key, true, defaultValue)
	}
	return logDecisionInt32(key, false, int32(val))
}

// EnvOrDefaultAsInt will return the Int value for a given key/default.
func EnvOrDefaultAsInt(key string, defaultValue int) int {
	result := os.Getenv(key)
	if len(result) == 0 {
		return logDecisionInt(key, true, defaultValue)
	}

	val, err := strconv.ParseInt(result, 10, 0)
	if err != nil {
		return logDecisionInt(key, true, defaultValue)
	}
	return logDecisionInt(key, false, int(val))
}

func logDecisionString(key string, usedDefault bool, value string) string {
	if usedDefault {
		logxi.Info("Used default instead of environment variable", "Env var", key, "Default", value)
		return value
	}
	logxi.Info("Used override environment variable", "Env var", key, "Value", value)
	return value
}

func logDecisionBool(key string, usedDefault bool, value bool) bool {
	if usedDefault {
		logxi.Info("Used default instead of environment variable", "Env var", key, "Default", value)
		return value
	}
	logxi.Info("Used override environment variable", "Env var", key, "Value", value)
	return value
}

func logDecisionInt64(key string, usedDefault bool, value int64) int64 {
	if usedDefault {
		logxi.Info("Used default instead of environment variable", "Env var", key, "Default", value)
		return value
	}
	logxi.Info("Used override environment variable", "Env var", key, "Value", value)
	return value
}

func logDecisionInt32(key string, usedDefault bool, value int32) int32 {
	if usedDefault {
		logxi.Info("Used default instead of environment variable", "Env var", key, "Default", value)
		return value
	}
	logxi.Info("Used override environment variable", "Env var", key, "Value", value)
	return value
}

func logDecisionInt(key string, usedDefault bool, value int) int {
	if usedDefault {
		logxi.Info("Used default instead of environment variable", "Env var", key, "Default", value)
		return value
	}
	logxi.Info("Used override environment variable", "Env var", key, "Value", value)
	return value
}
