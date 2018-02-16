package math

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/mangeshhendre/grpcjwt"
	"github.com/mangeshhendre/grpcutils"
	"github.com/mangeshhendre/jwtclient"
	pb "github.com/mangeshhendre/models/services_math_v1"
	"github.com/mangeshhendre/protocache"
	"github.com/mangeshhendre/tracer"
	logxi "github.com/mgutz/logxi/v1"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"gopkg.in/matryer/respond.v1"
)

// Server is the receiver struct around accessing the bgcheck stuff.
type Server struct {
	mathClient pb.MathClient
	conn       *grpc.ClientConn
	cache      *protocache.PC
	logger     logxi.Logger
	jsonpb     jsonpb.Marshaler
	tracer     *tracer.Tracer
	timeout    int64
}

// New is the init function that returns a bgcheck server
func New() (*Server, error) {

	// Get a protocache instance.
	cache, err := SetupProtocache()
	if err != nil {
		return nil, err
	}

	// Setup logging.
	logger := logxi.New("MathClient")
	logger.Info("Initialized by New")

	// Make a jwt client.
	jwtClientConfig := jwtclient.Config{
		AuthKey:    envOrDefault("LUGGAGE_GRPC_CLIENT_USERNAME", "USERNAME_UNSET"),
		AuthSecret: envOrDefault("LUGGAGE_GRPC_CLIENT_PASSWORD", "PASSWORD_UNSET"),
		URL:        envOrDefault("LUGGAGE_GRPC_AUTH_URL", "https://authentication."+envOrDefault("DOMAIN", "safeguardproperties.com")),
		Insecure:   false,
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
	transportCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})

	hostToDial := net.JoinHostPort(
		envOrDefault("LUGGAGE_GRPC_HOST", "mathsvc.grpc."+envOrDefault("DOMAIN", "safeguardproperties.com")),
		envOrDefault("LUGGAGE_GRPC_PORT", "8446"),
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

	client := pb.NewMathClient(conn)

	jsonpb := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "  ",
	}

	myTimeout, err := strconv.ParseInt(envOrDefault("GRPC_CLIENT_TIMEOUT", "15"), 10, 64)

	return &Server{
		mathClient: client,
		conn:       conn,
		cache:      cache,
		logger:     logger,
		jsonpb:     jsonpb,
		tracer:     tracer.New("graphite:8125", "spiglassapi", 1),
		timeout:    myTimeout,
	}, nil
}

//Close no warning
func (s *Server) Close() error {
	return s.conn.Close()
}

func envOrDefault(key, defaultValue string) string {
	foo := os.Getenv(key)
	if len(foo) > 0 {
		return foo
	}
	return defaultValue
}

//SetupProtocache no warning
func SetupProtocache() (*protocache.PC, error) {
	// Setup a protocache.
	servers := envOrDefault("MEMCACHE_SERVERS", "mem01:11211;mem01:11212;mem01:11213;mem02:11211;mem02:11212;mem03:11213;mem03:11211;mem03:11212;mem02:11213")

	cache := protocache.New("MATHSvc", servers)

	return cache, nil

}

// InitHandler is an indirection method for serving up content.
func InitHandler(router *mux.Router, chain *alice.Chain) error {
	handler, err := New()
	if err != nil {
		return fmt.Errorf("Unable to create handler: %v", err)
	}
	handler.logger.Info("InitHandler")

	router.Handle("/API/{version}/math/{action}/{number1}/{number2}", chain.ThenFunc(handler.grpcMathEndpoint)).Methods("GET")

	return nil
}

func (s Server) grpcMathEndpoint(w http.ResponseWriter, r *http.Request) {
	defer s.tracer.Statsd("grpcMathEndpoint", time.Now())

	ctx := r.Context()
	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(s.timeout)*time.Second)
	defer cancel()

	v := mux.Vars(r)
	possibleAction := v["action"]
	possibleNumber1 := v["number1"]
	possibleNumber2 := v["number2"]

	number1, err := strconv.ParseFloat(possibleNumber1, 64)
	if err != nil {
		s.logger.Warn("Unable to convert argument to an float", "Error", err)
		respond.WithStatus(w, r, http.StatusInternalServerError)
		return
	}

	number2, err := strconv.ParseFloat(possibleNumber2, 64)
	if err != nil {
		s.logger.Warn("Unable to convert argument2 to an float", "Error", err)
		respond.WithStatus(w, r, http.StatusInternalServerError)
		return
	}

	request := &pb.MathRequest{
		Number1: number1,
		Number2: number2,
	}

	var response = &pb.MathResponse{}

	if strings.ToLower(possibleAction) == "add" {
		response, err = s.mathClient.AddNumber(ctxWithTimeout, request)
	} else if strings.ToLower(possibleAction) == "multiply" {
		response, err = s.mathClient.MultiplyNumber(ctxWithTimeout, request)
	}
	if strings.ToLower(possibleAction) == "devide" {
		response, err = s.mathClient.DevideNumber(ctxWithTimeout, request)
	}
	if err != nil {
		if foo, ok := status.FromError(err); ok {
			// This is a GRPC error
			code := foo.Code()
			respond.With(w, r, grpcutils.HTTPStatusFromCode(code), err)
			return
		}
		respond.WithStatus(w, r, http.StatusInternalServerError)
		return
	}

	outBuffer := bytes.NewBuffer(nil)

	err = s.jsonpb.Marshal(outBuffer, response)
	if err != nil {
		respond.WithStatus(w, r, http.StatusInternalServerError)
		return
	}

	jsonWriter(w, outBuffer)
}

func jsonWriter(w http.ResponseWriter, outBuffer *bytes.Buffer) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(outBuffer.Bytes())
}
