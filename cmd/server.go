// cmd/server.go
package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sftp-protocol/network"
	"sftp-protocol/sftp"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	serverAddr    string
	serverRootDir string
	defaultUser   string
	defaultPass   string
	enablePubKey  bool
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the SFTP server",
	Long: `Start the SFTP server with the specified configuration.
The server will listen for incoming connections and handle file transfers.`,
	Run: func(cmd *cobra.Command, args []string) {
		startServer()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Add flags for server configuration
	serverCmd.Flags().StringVarP(&serverAddr, "address", "a", "127.0.0.1:2022", "Address and port to listen on")
	serverCmd.Flags().StringVarP(&serverRootDir, "root", "r", "", "Root directory for the server (default: temp directory)")
	serverCmd.Flags().StringVarP(&defaultUser, "user", "u", "", "Create a default user with this username")
	serverCmd.Flags().StringVarP(&defaultPass, "password", "p", "", "Password for the default user")
	serverCmd.Flags().BoolVarP(&enablePubKey, "enable-pubkey", "k", false, "Enable public key authentication for the default user")
}

func startServer() {
	fmt.Println("Starting SFTP server...")

	// Set up server root directory
	var serverDir string
	var err error
	if serverRootDir == "" {
		// Create a temporary directory if none specified
		serverDir, err = ioutil.TempDir("", "sftp-server-")
		if err != nil {
			log.Fatalf("Failed to create server directory: %v", err)
		}
		fmt.Printf("Using temporary directory: %s\n", serverDir)
	} else {
		// Use the specified directory
		serverDir = serverRootDir
		// Create it if it doesn't exist
		if _, err := os.Stat(serverDir); os.IsNotExist(err) {
			err = os.MkdirAll(serverDir, 0755)
			if err != nil {
				log.Fatalf("Failed to create server directory: %v", err)
			}
		}
		serverDir, err = filepath.Abs(serverDir)
		if err != nil {
			log.Fatalf("Failed to get absolute path: %v", err)
		}
		fmt.Printf("Using directory: %s\n", serverDir)
	}

	// Initialize authentication and session manager
	userStore := sftp.NewMemoryUserStore()
	auth := sftp.NewAuthenticator(userStore)
	sessionManager := sftp.NewSessionManager(auth, serverDir)

	// Create default user if credentials provided
	if defaultUser != "" {
		var pkPEM []byte
		if enablePubKey {
			pkKeyPair, err := sftp.GenerateKeyPair()
			if err != nil {
				log.Fatalf("Failed to generate key pair: %v", err)
			}
			pkPEM, err = sftp.EncodePublicKey(&pkKeyPair.PrivateKey.PublicKey)
			if err != nil {
				log.Fatalf("Failed to encode public key: %v", err)
			}

			// Save private key to a file for the user
			privKeyFile := filepath.Join(serverDir, defaultUser+".key")
			privKeyPEM, err := sftp.EncodePrivateKey(pkKeyPair.PrivateKey)
			if err != nil {
				log.Fatalf("Failed to encode private key: %v", err)
			}
			if err := ioutil.WriteFile(privKeyFile, privKeyPEM, 0600); err != nil {
				log.Fatalf("Failed to save private key: %v", err)
			}
			fmt.Printf("Generated private key for %s: %s\n", defaultUser, privKeyFile)
		}

		err = auth.RegisterUser(defaultUser, defaultPass, pkPEM)
		if err != nil {
			log.Fatalf("Failed to register default user: %v", err)
		}
		fmt.Printf("Registered user: %s\n", defaultUser)
	}

	// Start server
	server := network.NewServer(serverAddr, sessionManager, auth)

	// Handle graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nShutting down server...")
		server.Stop()
	}()

	fmt.Printf("Server listening on %s\n", serverAddr)
	fmt.Println("Press Ctrl+C to stop the server")

	err = server.Start()
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
