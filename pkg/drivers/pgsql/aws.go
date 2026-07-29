package pgsql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/sirupsen/logrus"
)

// awsIAMConnOptions returns the pgx stdlib connection options required to
// authenticate to Postgres via RDS IAM when no password is supplied in the
// datastore DSN. The signing credentials are sourced from the AWS default
// credential provider chain. When a password is present it returns nil,
// leaving normal password authentication in place.
func awsIAMConnOptions(ctx context.Context, config *pgx.ConnConfig) ([]stdlib.OptionOpenDB, error) {
	if config.Password != "" {
		return nil, nil
	}

	logrus.Infof("No password supplied in datastore DSN; using AWS default credential provider to generate RDS IAM authentication tokens for user %q", config.User)
	if config.TLSConfig == nil {
		logrus.Warnf("RDS IAM authentication requires TLS but sslmode appears to be disabled; the connection is likely to be rejected")
	}

	opt, err := awsIAMAuthOption(ctx)
	if err != nil {
		return nil, err
	}
	return []stdlib.OptionOpenDB{opt}, nil
}

// awsIAMAuthOption returns a pgx stdlib BeforeConnect option that populates the
// connection password with a freshly generated RDS IAM authentication token,
// sourcing the signing credentials from the AWS default credential provider
// chain. The token is regenerated for every new physical connection, so the
// ~15 minute token lifetime is honoured as the connection pool opens and
// recycles connections.
func awsIAMAuthOption(ctx context.Context) (stdlib.OptionOpenDB, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration for RDS IAM authentication: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("no AWS region configured for RDS IAM authentication; set AWS_REGION or configure a region in the AWS profile/config")
	}

	hook := func(ctx context.Context, connConfig *pgx.ConnConfig) error {
		endpoint := net.JoinHostPort(connConfig.Host, strconv.Itoa(int(connConfig.Port)))
		token, err := awsauth.BuildAuthToken(ctx, endpoint, awsCfg.Region, connConfig.User, awsCfg.Credentials)
		if err != nil {
			return fmt.Errorf("failed to generate RDS IAM authentication token: %w", err)
		}
		connConfig.Password = token
		return nil
	}
	return stdlib.OptionBeforeConnect(hook), nil
}
