package basichealth

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	respond "gopkg.in/matryer/respond.v1"
)

// InitHandler will add this handler to the rest of the uniqueness.
func InitHandler(router *mux.Router, chain *alice.Chain) error {
	router.Path("/healthz").Handler(chain.ThenFunc(healthEndpoint)).Methods("GET")
	return nil
}

func healthEndpoint(w http.ResponseWriter, r *http.Request) {
	respond.WithStatus(w, r, http.StatusOK)
	return
}
