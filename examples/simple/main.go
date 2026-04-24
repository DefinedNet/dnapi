package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/DefinedNet/dnapi"
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

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := dnapi.NewClient("api-example/1.0", *server)

	// initial enrollment example
	config, pkey, creds, meta, err := c.Enroll(context.Background(), logger, *code)
	if err != nil {
		logger.Error("Failed to enroll", "error", err)
		os.Exit(1)
	}

	config, err = dnapi.InsertConfigPrivateKey(config, pkey)
	if err != nil {
		logger.Error("Failed to insert private key into config", "error", err)
		os.Exit(1)
	}

	fmt.Printf(
		"Host ID: %s (Org: %s, ID: %s), Counter: %d, Config:\n\n%s\n",
		creds.HostID,
		meta.Org.Name,
		meta.Org.ID,
		creds.Counter,
		config,
	)

	// loop and check for updates example
	for {
		logger.Info("Waiting 60 seconds to check for update")
		time.Sleep(60 * time.Second)

		// check for an update and perform the update if available
		updateAvailable, err := c.CheckForUpdate(context.Background(), *creds)
		if err != nil {
			logger.Error("Failed to check for update", "error", err)
			continue
		}

		if updateAvailable {
			// be careful not to blow away creds in case err != nil
			// another option is to pass credentials by reference and let DoUpdate modify the struct if successful but
			// this makes it less obvious to the caller that they need to save the new credentials to disk
			config, pkey, newCreds, meta, err := c.DoUpdate(context.Background(), *creds)
			if err != nil {
				logger.Error("Failed to perform update", "error", err)
				continue
			}

			config, err = dnapi.InsertConfigPrivateKey(config, pkey)
			if err != nil {
				logger.Error("Failed to insert private key into config", "error", err)
				continue
			}

			creds = newCreds

			fmt.Printf("Counter: %d, config:\n\n%s\nmeta:\n%+v\n", creds.Counter, config, meta)

			// XXX Now would be a good time to save both the new config and credentials to disk and reload Nebula.
		}
	}
}
