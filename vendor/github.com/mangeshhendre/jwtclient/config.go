package jwtclient

// Config is the package configuration struct that configures the package.
type Config struct {
	AuthKey    string
	AuthSecret string
	URL        string
	Insecure   bool
}
