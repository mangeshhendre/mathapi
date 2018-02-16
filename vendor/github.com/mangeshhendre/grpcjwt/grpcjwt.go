package grpcjwt

import (
	"fmt"
	"sync"

	"github.com/mangeshhendre/jwtclient"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

// Creds is our PerRPCCredentials implementation receiver struct.
type Creds struct {
	mu     sync.Mutex
	client *jwtclient.Client
}

// NewFromClient is used to create a new grpc credentials receiver which conforms to the credentials interface.
func NewFromClient(client *jwtclient.Client) (credentials.PerRPCCredentials, error) {

	_, RetrieveErr := client.RetrieveToken()
	if RetrieveErr != nil {
		return nil, fmt.Errorf("Unable to authenticate: %v", RetrieveErr)
	}

	return &Creds{
		client: client,
	}, nil
}

// GetRequestMetadata will retrieve a JWT from the provided client.
func (c *Creds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	token, err := c.client.RetrieveToken()
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate: %v", err)
	}

	return map[string]string{"authorization": "bearer " + token}, nil
}

// RequireTransportSecurity is required by the interface and should return true.
// TODO:  Return true.
func (c *Creds) RequireTransportSecurity() bool {
	return true
}
