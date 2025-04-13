// cmd/client.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath" // Needed for download command
	"sftp-protocol/network"
	"sftp-protocol/sftp"

	"github.com/spf13/cobra"
)

// --- Existing variables (username, password, identityFile, serverAddress) remain the same ---
var (
	// Global client flags
	serverAddress string

	// Command-specific flags (accessed via cmd.Flags().Get... in Run)
	username     string
	password     string
	identityFile string // Path to the private key file
)

// --- clientCmd and loginCmd remain the same ---
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "SFTP client operations",
	Long:  `Perform SFTP client operations like file transfers using password or key authentication.`,
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Test authentication with the SFTP server",
	Long: `Connects and authenticates with the SFTP server using username/password OR public key.
This command is primarily for testing connectivity and authentication.
It does NOT establish a persistent session for subsequent commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		// --- Login Run function remains the same ---
		user, _ := cmd.Flags().GetString("username")
		pass, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("identity-file")

		// Validation
		if user == "" { /* ... */
			return
		}
		if pass == "" && keyFile == "" { /* ... */
			return
		}
		if pass != "" && keyFile != "" { /* ... */
			pass = ""
		}

		// Connect
		client := network.NewClient()
		err := client.Connect(serverAddress)
		if err != nil { /* ... */
			return
		}
		defer client.Close()
		fmt.Printf("Connected to server at %s\n", serverAddress)

		// Authenticate
		var authResp *sftp.UserAuthResponse
		var authErr error
		authMethod := "Password"
		if keyFile != "" {
			authMethod = "Public Key"
			fmt.Printf("Attempting public key authentication using key: %s\n", keyFile)
			keyBytes, errRead := os.ReadFile(keyFile)
			if errRead != nil { /* ... */
				return
			}
			privateKey, errDecode := sftp.DecodePrivateKey(keyBytes)
			if errDecode != nil { /* ... */
				return
			}
			authResp, authErr = client.AuthenticatePublicKey(user, privateKey)
		} else if pass != "" {
			fmt.Println("Attempting password authentication...")
			authResp, authErr = client.AuthenticatePassword(user, pass)
		} else { /* ... */
			return
		}

		// Check Auth Result
		if authErr != nil { /* ... */
			return
		}
		if authResp == nil || !authResp.Success { /* ... */
			return
		}

		fmt.Printf("%s authentication test successful! Session ID for this connection was: %s\n", authMethod, authResp.SessionID)
		fmt.Println("Connection will now close.")
	},
}

// --- uploadCmd remains the same ---
var uploadCmd = &cobra.Command{
	Use:   "upload [local_file] [remote_path]",
	Short: "Upload a file to the SFTP server",
	Long: `Connects, authenticates (using password or public key), uploads a local file, and disconnects.
Requires either a password (-p) or an identity file (-i) for authentication.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		// --- Upload Run function remains the same ---
		localFile := args[0]
		remotePath := args[1]
		user, _ := cmd.Flags().GetString("username")
		pass, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("identity-file")

		// Validation
		if user == "" { /* ... */
			return
		}
		if pass == "" && keyFile == "" { /* ... */
			return
		}
		if pass != "" && keyFile != "" { /* ... */
			pass = ""
		}
		fileInfo, err := os.Stat(localFile)
		if err != nil { /* ... */
			return
		}
		if fileInfo.IsDir() { /* ... */
			return
		}

		// Connect
		client := network.NewClient()
		err = client.Connect(serverAddress)
		if err != nil { /* ... */
			return
		}
		defer client.Close()
		fmt.Printf("Connected to server at %s\n", serverAddress)

		// Authenticate
		var authResp *sftp.UserAuthResponse
		var authErr error
		authMethod := "Password"
		if keyFile != "" {
			authMethod = "Public Key"
			fmt.Printf("Attempting public key authentication using key: %s\n", keyFile)
			keyBytes, errRead := os.ReadFile(keyFile)
			if errRead != nil { /* ... */
				return
			}
			privateKey, errDecode := sftp.DecodePrivateKey(keyBytes)
			if errDecode != nil { /* ... */
				return
			}
			authResp, authErr = client.AuthenticatePublicKey(user, privateKey)
		} else if pass != "" {
			fmt.Println("Attempting password authentication...")
			authResp, authErr = client.AuthenticatePassword(user, pass)
		} else { /* ... */
			return
		}

		// Check Auth Result
		if authErr != nil { /* ... */
			return
		}
		if authResp == nil || !authResp.Success { /* ... */
			return
		}
		fmt.Printf("%s authentication successful (Session ID: %s)\n", authMethod, authResp.SessionID)

		// Upload
		fmt.Printf("Uploading %s to %s...\n", localFile, remotePath)
		err = client.UploadFile(localFile, remotePath)
		if err != nil { /* ... */
			return
		}
		fmt.Printf("File upload successful!\n")
		fmt.Printf("  Local file: %s\n", localFile)
		fmt.Printf("  Remote path: %s\n", remotePath)
		fmt.Printf("  File size: %d bytes\n", fileInfo.Size())
	},
}

// --- NEW: downloadCmd ---
var downloadCmd = &cobra.Command{
	Use:   "download [remote_path] [local_path]",
	Short: "Download a file from the SFTP server",
	Long: `Connects, authenticates (using password or public key), downloads a remote file, and disconnects.
Requires either a password (-p) or an identity file (-i) for authentication.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		remotePath := args[0]
		localPath := args[1]

		// Get flags
		user, _ := cmd.Flags().GetString("username")
		pass, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("identity-file")

		// --- Validation ---
		if user == "" {
			fmt.Println("Error: Username (-u, --username) is required.")
			return
		}
		if pass == "" && keyFile == "" {
			fmt.Println("Error: Authentication required. Please provide either a password (-p) or an identity file (-i).")
			return
		}
		if pass != "" && keyFile != "" {
			fmt.Println("Warning: Both password (-p) and identity file (-i) provided. Using identity file.")
			pass = "" // Prioritize key file
		}
		// Optional: Check if local path's directory exists, create if not? Or let DownloadFile handle it.
		// For now, assume DownloadFile handles creating the file.

		// --- Connect ---
		client := network.NewClient()
		err := client.Connect(serverAddress)
		if err != nil {
			fmt.Printf("Failed to connect to server: %v\n", err)
			return
		}
		defer client.Close()
		fmt.Printf("Connected to server at %s\n", serverAddress)

		// --- Authenticate ---
		var authResp *sftp.UserAuthResponse
		var authErr error
		authMethod := "Password"
		if keyFile != "" {
			authMethod = "Public Key"
			fmt.Printf("Attempting public key authentication using key: %s\n", keyFile)
			keyBytes, errRead := os.ReadFile(keyFile)
			if errRead != nil {
				fmt.Printf("Error reading private key file '%s': %v\n", keyFile, errRead)
				return
			}
			privateKey, errDecode := sftp.DecodePrivateKey(keyBytes)
			if errDecode != nil {
				fmt.Printf("Error decoding private key from file '%s': %v\n", keyFile, errDecode)
				return
			}
			authResp, authErr = client.AuthenticatePublicKey(user, privateKey)
		} else if pass != "" {
			fmt.Println("Attempting password authentication...")
			authResp, authErr = client.AuthenticatePassword(user, pass)
		} else {
			fmt.Println("Error: No authentication method determined.")
			return
		}

		// --- Check Auth Result ---
		if authErr != nil {
			fmt.Printf("%s authentication failed: %v\n", authMethod, authErr)
			return
		}
		if authResp == nil || !authResp.Success {
			errMsg := "Invalid credentials or key."
			if authResp != nil && authResp.Message != "" {
				errMsg = authResp.Message
			}
			fmt.Printf("%s authentication failed: %s\n", authMethod, errMsg)
			return
		}
		fmt.Printf("%s authentication successful (Session ID: %s)\n", authMethod, authResp.SessionID)

		// --- Download the file ---
		fmt.Printf("Downloading %s to %s...\n", remotePath, localPath)
		// Assuming DownloadFile uses the authenticated client state
		err = client.DownloadFile(remotePath, localPath)
		if err != nil {
			fmt.Printf("Download failed: %v\n", err)
			// Attempt to remove partially downloaded file? Optional.
			// os.Remove(localPath)
			return
		}

		// Optional: Verify downloaded file size locally
		localFileInfo, errStat := os.Stat(localPath)
		if errStat != nil {
			fmt.Printf("Warning: Failed to stat downloaded file locally '%s': %v\n", localPath, errStat)
		}

		fmt.Printf("File download successful!\n")
		fmt.Printf("  Remote path: %s\n", remotePath)
		// Use filepath.Abs for potentially clearer local path output
		absLocalPath, _ := filepath.Abs(localPath)
		fmt.Printf("  Local path: %s\n", absLocalPath)
		if errStat == nil {
			fmt.Printf("  File size: %d bytes\n", localFileInfo.Size())
		}
	},
}

// --- NEW: mkdirCmd ---
var mkdirCmd = &cobra.Command{
	Use:   "mkdir [remote_path]",
	Short: "Create a directory on the SFTP server",
	Long: `Connects, authenticates (using password or public key), creates a directory, and disconnects.
Requires either a password (-p) or an identity file (-i) for authentication.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		remoteDirPath := args[0]

		// Get flags
		user, _ := cmd.Flags().GetString("username")
		pass, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("identity-file")

		// --- Validation ---
		if user == "" {
			fmt.Println("Error: Username (-u, --username) is required.")
			return
		}
		if pass == "" && keyFile == "" {
			fmt.Println("Error: Authentication required. Please provide either a password (-p) or an identity file (-i).")
			return
		}
		if pass != "" && keyFile != "" {
			fmt.Println("Warning: Both password (-p) and identity file (-i) provided. Using identity file.")
			pass = "" // Prioritize key file
		}

		// --- Connect ---
		client := network.NewClient()
		err := client.Connect(serverAddress)
		if err != nil {
			fmt.Printf("Failed to connect to server: %v\n", err)
			return
		}
		defer client.Close()
		fmt.Printf("Connected to server at %s\n", serverAddress)

		// --- Authenticate ---
		var authResp *sftp.UserAuthResponse
		var authErr error
		authMethod := "Password"
		if keyFile != "" {
			authMethod = "Public Key"
			fmt.Printf("Attempting public key authentication using key: %s\n", keyFile)
			keyBytes, errRead := os.ReadFile(keyFile)
			if errRead != nil {
				fmt.Printf("Error reading private key file '%s': %v\n", keyFile, errRead)
				return
			}
			privateKey, errDecode := sftp.DecodePrivateKey(keyBytes)
			if errDecode != nil {
				fmt.Printf("Error decoding private key from file '%s': %v\n", keyFile, errDecode)
				return
			}
			authResp, authErr = client.AuthenticatePublicKey(user, privateKey)
		} else if pass != "" {
			fmt.Println("Attempting password authentication...")
			authResp, authErr = client.AuthenticatePassword(user, pass)
		} else {
			fmt.Println("Error: No authentication method determined.")
			return
		}

		// --- Check Auth Result ---
		if authErr != nil {
			fmt.Printf("%s authentication failed: %v\n", authMethod, authErr)
			return
		}
		if authResp == nil || !authResp.Success {
			errMsg := "Invalid credentials or key."
			if authResp != nil && authResp.Message != "" {
				errMsg = authResp.Message
			}
			fmt.Printf("%s authentication failed: %s\n", authMethod, errMsg)
			return
		}
		fmt.Printf("%s authentication successful (Session ID: %s)\n", authMethod, authResp.SessionID)

		// --- Create Directory ---
		fmt.Printf("Creating directory %s...\n", remoteDirPath)
		// Assume Mkdir takes path and returns a response indicating success/failure
		// Adjust based on the actual signature of client.Mkdir
		// Assuming it returns *sftp.SimpleResponse based on reference code's check `!mkdirResp.Success`
		mkdirResp, err := client.Mkdir(remoteDirPath)
		if err != nil {
			fmt.Printf("Mkdir operation failed: %v\n", err)
			return
		}
		if mkdirResp == nil || !mkdirResp.Success {
			errMsg := "Server indicated failure."
			if mkdirResp != nil && mkdirResp.Message != "" {
				errMsg = mkdirResp.Message
			}
			fmt.Printf("Failed to create directory '%s': %s\n", remoteDirPath, errMsg)
			return
		}

		fmt.Printf("Successfully created directory '%s'\n", remoteDirPath)
	},
}

// --- NEW: lsCmd ---
var lsCmd = &cobra.Command{
	Use:   "ls [remote_path]",
	Short: "List files and directories on the SFTP server",
	Long: `Connects, authenticates (using password or public key), lists directory contents, and disconnects.
Use '.' for the current directory.
Requires either a password (-p) or an identity file (-i) for authentication.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		remoteDirPath := args[0]

		// Get flags
		user, _ := cmd.Flags().GetString("username")
		pass, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("identity-file")

		// --- Validation ---
		if user == "" {
			fmt.Println("Error: Username (-u, --username) is required.")
			return
		}
		if pass == "" && keyFile == "" {
			fmt.Println("Error: Authentication required. Please provide either a password (-p) or an identity file (-i).")
			return
		}
		if pass != "" && keyFile != "" {
			fmt.Println("Warning: Both password (-p) and identity file (-i) provided. Using identity file.")
			pass = "" // Prioritize key file
		}

		// --- Connect ---
		client := network.NewClient()
		err := client.Connect(serverAddress)
		if err != nil {
			fmt.Printf("Failed to connect to server: %v\n", err)
			return
		}
		defer client.Close()
		fmt.Printf("Connected to server at %s\n", serverAddress)

		// --- Authenticate ---
		var authResp *sftp.UserAuthResponse
		var authErr error
		authMethod := "Password"
		if keyFile != "" {
			authMethod = "Public Key"
			fmt.Printf("Attempting public key authentication using key: %s\n", keyFile)
			keyBytes, errRead := os.ReadFile(keyFile)
			if errRead != nil {
				fmt.Printf("Error reading private key file '%s': %v\n", keyFile, errRead)
				return
			}
			privateKey, errDecode := sftp.DecodePrivateKey(keyBytes)
			if errDecode != nil {
				fmt.Printf("Error decoding private key from file '%s': %v\n", keyFile, errDecode)
				return
			}
			authResp, authErr = client.AuthenticatePublicKey(user, privateKey)
		} else if pass != "" {
			fmt.Println("Attempting password authentication...")
			authResp, authErr = client.AuthenticatePassword(user, pass)
		} else {
			fmt.Println("Error: No authentication method determined.")
			return
		}

		// --- Check Auth Result ---
		if authErr != nil {
			fmt.Printf("%s authentication failed: %v\n", authMethod, authErr)
			return
		}
		if authResp == nil || !authResp.Success {
			errMsg := "Invalid credentials or key."
			if authResp != nil && authResp.Message != "" {
				errMsg = authResp.Message
			}
			fmt.Printf("%s authentication failed: %s\n", authMethod, errMsg)
			return
		}
		fmt.Printf("%s authentication successful (Session ID: %s)\n", authMethod, authResp.SessionID)

		// --- List Files ---
		fmt.Printf("Listing contents of %s...\n", remoteDirPath)
		// Assume ListFiles takes path and returns a response containing a list of files
		// Adjust based on the actual signature of client.ListFiles
		// Assuming *sftp.ListFilesResponse based on reference code `listResp.Files`
		listResp, err := client.ListFiles(remoteDirPath)
		if err != nil {
			fmt.Printf("ListFiles operation failed: %v\n", err)
			return
		}
		if listResp == nil || !listResp.Success {
			errMsg := "Server indicated failure."
			if listResp != nil && listResp.Message != "" {
				errMsg = listResp.Message
			}
			fmt.Printf("Failed to list directory '%s': %s\n", remoteDirPath, errMsg)
			return
		}

		fmt.Println("Directory listing:")
		if len(listResp.Files) == 0 {
			fmt.Println("  (empty directory)")
		} else {
			// Adjust formatting as needed
			for _, f := range listResp.Files {
				fileType := "File"
				if f.IsDirectory {
					fileType = "Dir "
				}
				// Pad size for alignment, for example
				fmt.Printf("  %s %10d %s\n", fileType, f.Size, f.Name)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)

	// --- Global Client Flags (Persistent) ---
	clientCmd.PersistentFlags().StringVarP(&serverAddress, "server", "s", "127.0.0.1:2022", "Server address (host:port)")

	// --- Login Command Flags ---
	clientCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringP("username", "u", "", "Username for authentication")
	loginCmd.Flags().StringP("password", "p", "", "Password for authentication (optional if -i provided)")
	loginCmd.Flags().StringP("identity-file", "i", "", "Path to private key file for auth (optional if -p provided)")
	loginCmd.MarkFlagRequired("username")

	// --- Upload Command Flags ---
	clientCmd.AddCommand(uploadCmd)
	uploadCmd.Flags().StringP("username", "u", "", "Username for authentication")
	uploadCmd.Flags().StringP("password", "p", "", "Password for authentication (optional if -i provided)")
	uploadCmd.Flags().StringP("identity-file", "i", "", "Path to private key file for auth (optional if -p provided)")
	uploadCmd.MarkFlagRequired("username")

	// --- Download Command Flags ---
	clientCmd.AddCommand(downloadCmd)
	downloadCmd.Flags().StringP("username", "u", "", "Username for authentication")
	downloadCmd.Flags().StringP("password", "p", "", "Password for authentication (optional if -i provided)")
	downloadCmd.Flags().StringP("identity-file", "i", "", "Path to private key file for auth (optional if -p provided)")
	downloadCmd.MarkFlagRequired("username")

	// --- Mkdir Command Flags ---
	clientCmd.AddCommand(mkdirCmd)
	mkdirCmd.Flags().StringP("username", "u", "", "Username for authentication")
	mkdirCmd.Flags().StringP("password", "p", "", "Password for authentication (optional if -i provided)")
	mkdirCmd.Flags().StringP("identity-file", "i", "", "Path to private key file for auth (optional if -p provided)")
	mkdirCmd.MarkFlagRequired("username")

	// --- Ls Command Flags ---
	clientCmd.AddCommand(lsCmd)
	lsCmd.Flags().StringP("username", "u", "", "Username for authentication")
	lsCmd.Flags().StringP("password", "p", "", "Password for authentication (optional if -i provided)")
	lsCmd.Flags().StringP("identity-file", "i", "", "Path to private key file for auth (optional if -p provided)")
	lsCmd.MarkFlagRequired("username")
}
