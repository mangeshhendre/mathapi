package jwtauthfunc

import (
	context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	jwt "github.com/dgrijalva/jwt-go"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

// Authorizer is the private keyspace that validates stuff.
type Authorizer struct {
	parser  *jwt.Parser
	keyFunc jwt.Keyfunc
}

// New gets me a struct into which I inject my parser and an authfunc.
func New(parser *jwt.Parser, kf jwt.Keyfunc) (*Authorizer, error) {
	return &Authorizer{
		parser:  parser,
		keyFunc: kf,
	}, nil
}

// Authorize is the method used to actually authorize
func (a *Authorizer) Authorize(ctx context.Context) (context.Context, error) {
	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "Unable to retrieve token: %v", err)
	}
	_, err = a.parser.Parse(token, a.keyFunc)
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
	}
	return ctx, nil

}
