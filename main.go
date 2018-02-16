package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/mangeshhendre/basichealth"
	"github.com/mangeshhendre/jwtclient"
	"github.com/mangeshhendre/jwtcookie"
	"github.com/mangeshhendre/mathapi/handlers/math"
	logxi "github.com/mgutz/logxi/v1"
	"github.com/rs/cors"
)

const timeout = 90

func main() {
	var (
		cn            = flag.String("cookie_name", "Bearer", "The name of the cookie element which contains the JWT")
		keyPath       = flag.String("key_path", "server.key", "The key to use for SSL encryption")
		certPath      = flag.String("cert_path", "server.crt", "The cert to use for SSL encryption")
		jwtCertPath   = flag.String("jwt_cert_path", "jwt_certs", "The path in which to locate JWT certificates, files should be named ISSUER.pem where ISSUER is the issuer expected.")
		serverAddress = flag.String("address", "0.0.0.0", "The address to listen on")
		serverPort    = flag.String("port", "8443", "The port to listen on")
		skipAuth      = flag.Bool("skip_auth", false, "Should we skip authentication?")
		debug         = flag.Bool("debug", false, "Should we debug?")
	)

	flag.Parse()

	logger := logxi.New("mathapi")

	// Setup keyfunc
	keyFunc, err := jwtclient.KeyFuncFromCertDir(*jwtCertPath)
	if err != nil {
		logger.Fatal("Unable to create key function: ", "Error", err)
	}

	// First we need a router.
	router := mux.NewRouter()

	// Now we need a jwtcookie middleware
	JWTC, err := jwtcookie.New(
		jwtcookie.CookieName(*cn),
		jwtcookie.KeyFunc(keyFunc),
	)
	if err != nil {
		logger.Fatal("Unable to create jwt cookie middleware", "Error", err)
	}

	// CORS it up...
	corsMiddleware := cors.New(cors.Options{
		AllowOriginFunc:  everyone,
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Accept"},
		Debug:            *debug,
	})

	// Throw in some stats for good measure.
	//SMW := statsdmw.New("graphite:8125", "mathapi", .2)

	//authChain := alice.New(timeoutHandler, recoveryHandler, loggingHandler, corsMiddleware.Handler, SMW.Statsd, JWTC.JWTRedirect)
	//openChain := alice.New(timeoutHandler, recoveryHandler, loggingHandler, corsMiddleware.Handler, SMW.Statsd)
	authChain := alice.New(timeoutHandler, recoveryHandler, loggingHandler, corsMiddleware.Handler, JWTC.JWTRedirect)
	openChain := alice.New(timeoutHandler, recoveryHandler, loggingHandler, corsMiddleware.Handler)

	if *skipAuth {
		authChain = openChain
	}

	// Now we start registering handlers.
	err = basichealth.InitHandler(router, &openChain)
	if err != nil {
		logger.Fatal("Unable to register health handler", "Error", err)
	}

	err = math.InitHandler(router, &authChain)
	if err != nil {
		logger.Fatal("Unable to initialize and register math handler", "Error", err)
	}

	logger.Info("Startup complete")

	log.Fatal(http.ListenAndServeTLS(net.JoinHostPort(*serverAddress, *serverPort), *certPath, *keyPath, router))
}

func everyone(origin string) bool {
	return true
}

func timeoutHandler(h http.Handler) http.Handler {
	return http.TimeoutHandler(h, timeout*time.Second, "timed out")
}

func recoveryHandler(h http.Handler) http.Handler {
	return ghandlers.RecoveryHandler()(h)
}

func loggingHandler(h http.Handler) http.Handler {
	return ghandlers.LoggingHandler(os.Stdout, h)
}
