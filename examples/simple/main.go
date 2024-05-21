package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/DefinedNet/dnapi"
	"github.com/sirupsen/logrus"
)

func main() {
	server := flag.String("server", "https://api.defined.net", "API server (e.g. https://api.defined.net)")
	code := flag.String("code", "", "enrollment code")
	flag.Parse()

	if *code == "" {
		fmt.Println("-code flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	logger := logrus.New()
	c := dnapi.NewClient("api-example/1.0", *server)

	// initial enrollment example
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, pkey, creds, meta, err := c.Enroll(ctx, logger, *code)
	if err != nil {
		logger.WithError(err).Error("Failed to enroll")
	}

	config, err = dnapi.InsertConfigPrivateKey(config, pkey)
	if err != nil {
		logger.WithError(err).Error("Failed to insert private key into config")
	}

	fmt.Printf(
		"Host ID: %s (Org: %s, ID: %s), Counter: %d, Config:\n\n%s\n",
		creds.HostID,
		meta.OrganizationName,
		meta.OrganizationID,
		creds.Counter,
		config,
	)

	// loop and check for updates example
	for {
		logger.Info("Waiting 60 seconds to check for update")
		time.Sleep(60 * time.Second)

		// check for an update and perform the update if available
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		updateAvailable, err := c.CheckForUpdate(ctx, *creds)
		if err != nil {
			logger.WithError(err).Error("Failed to check for update")
			continue
		}

		if updateAvailable {
			// be careful not to blow away creds in case err != nil
			// another option is to pass credentials by reference and let DoUpdate modify the struct if successful but
			// this makes it less obvious to the caller that they need to save the new credentials to disk
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			config, pkey, newCreds, err := c.DoUpdate(ctx, *creds)
			if err != nil {
				logger.WithError(err).Error("Failed to perform update")
				continue
			}

			config, err = dnapi.InsertConfigPrivateKey(config, pkey)
			if err != nil {
				logger.WithError(err).Error("Failed to insert private key into config")
			}

			creds = newCreds

			fmt.Printf("Counter: %d, config:\n\n%s\n", creds.Counter, config)

			// XXX Now would be a good time to save both the new config and credentials to disk and reload Nebula.
		}
	}
}
