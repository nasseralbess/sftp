/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sftp-protocol",
	Short: "A simple SFTP protocol implementation in Go",
	Long: `
	SFTP Protocol CLI Documentation

A secure file transfer protocol (SFTP) implementation in Go with both
client and server functionality. This application provides commands for
running an SFTP server and performing client operations such as
authentication, file uploads/downloads, directory management, and key
generation.

Root Command

The root command serves as the entry point to the application.

	Usage:
	sftp-protocol [command]

	Available Commands:
	client      SFTP client operations
	server      Start the SFTP server
	help        Help about any command

	Flags:
	-h, --help   help for sftp-protocol

Server Command

Start an SFTP server to handle incoming connections and file transfers.

	Usage:
	sftp-protocol server [flags]

	Flags:
	-a, --address string     Address and port to listen on (default "127.0.0.1:2022")
	-h, --help               help for server
	-k, --pubkey-file string Path to the default user's public key file (PEM format) for public key authentication
	-p, --password string    Password for the default user
	-r, --root string        Root directory for the server (default: temp directory)
	-u, --user string        Create a default user with this username

The server will start and listen for connections at the specified
address. If no root directory is specified, a temporary directory will
be created. A default user can be configured with either password or
public key authentication.

Client Commands

The client provides various commands for interacting with an SFTP
server.

Client Base Command

	Usage:
	sftp-protocol client [command]

	Available Commands:
	login       Test authentication with the SFTP server
	upload      Upload a file to the SFTP server
	download    Download a file from the SFTP server
	mkdir       Create a directory on the SFTP server
	ls          List files and directories on the SFTP server
	keygen      Generate a new ECDSA key pair for SFTP authentication

	Flags:
	-h, --help            help for client
	-s, --server string   Server address (host:port) (default "127.0.0.1:2022")

Login Command

Test authentication with the SFTP server without performing any file
operations.

	Usage:
	sftp-protocol client login [flags]

	Flags:
	-h, --help                   help for login
	-i, --identity-file string   Path to private key file for auth (optional if -p provided)
	-p, --password string        Password for authentication (optional if -i provided)
	-u, --username string        Username for authentication (required)

This command connects and authenticates with the SFTP server using a
username/password or public key. It's primarily for testing connectivity
and authentication and does not establish a persistent session.

Upload Command

Upload a local file to the SFTP server.

	Usage:
	sftp-protocol client upload [local_file] [remote_path] [flags]

	Arguments:
	[local_file]    Path to the local file to upload
	[remote_path]   Destination path on the server

	Flags:
	-h, --help                   help for upload
	-i, --identity-file string   Path to private key file for auth (optional if -p provided)
	-p, --password string        Password for authentication (optional if -i provided)
	-u, --username string        Username for authentication (required)

This command connects to the server, authenticates using the provided
credentials, uploads the specified file, and then disconnects.

Download Command

Download a file from the SFTP server to the local system.

	Usage:
	sftp-protocol client download [remote_path] [local_path] [flags]

	Arguments:
	[remote_path]   Path to the file on the server
	[local_path]    Destination path on the local system

	Flags:
	-h, --help                   help for download
	-i, --identity-file string   Path to private key file for auth (optional if -p provided)
	-p, --password string        Password for authentication (optional if -i provided)
	-u, --username string        Username for authentication (required)

This command connects to the server, authenticates, downloads the
specified file, and disconnects.

Mkdir Command

Create a directory on the SFTP server.

	Usage:
	sftp-protocol client mkdir [remote_path] [flags]

	Arguments:
	[remote_path]   Path of the directory to create on the server

	Flags:
	-h, --help                   help for mkdir
	-i, --identity-file string   Path to private key file for auth (optional if -p provided)
	-p, --password string        Password for authentication (optional if -i provided)
	-u, --username string        Username for authentication (required)

This command creates a new directory at the specified path on the SFTP
server.

Ls Command

List files and directories on the SFTP server.

	Usage:
	sftp-protocol client ls [remote_path] [flags]

	Arguments:
	[remote_path]   Path to list on the server (use '.' for current directory)

	Flags:
	-h, --help                   help for ls
	-i, --identity-file string   Path to private key file for auth (optional if -p provided)
	-p, --password string        Password for authentication (optional if -i provided)
	-u, --username string        Username for authentication (required)

This command displays a list of files and directories at the specified
path on the SFTP server.

Keygen Command

Generate a new ECDSA key pair for SFTP authentication.

	Usage:
	sftp-protocol client keygen [flags]

	Flags:
	-f, --force           Overwrite existing key files
	-h, --help            help for keygen
	-o, --output string   Base path/filename for the key files (e.g., 'my_key') (required)

This command generates a new ECDSA private and public key pair suitable
for authentication with the SFTP server. The private key is saved to the
specified output file and the public key to <output_file>.pub.

Examples

Starting a Server

Start an SFTP server with a default user:


Start server with password authentication
sftp-protocol server -u testuser -p secretpassword -r /path/to/server/root

Start server with public key authentication
sftp-protocol server -u testuser -k /path/to/user_pubkey.pub -r /path/to/server/root


Client Operations

Generate a key pair for authentication:


sftp-protocol client keygen -o my_sftp_key


Test authentication with the server:


Password authentication
sftp-protocol client login -u testuser -p secretpassword

Public key authentication
sftp-protocol client login -u testuser -i my_sftp_key


Upload a file:


sftp-protocol client upload local_file.txt /remote/path/file.txt -u testuser -p secretpassword


Download a file:


sftp-protocol client download /remote/path/file.txt local_copy.txt -u testuser -i my_sftp_key


List directory contents:


sftp-protocol client ls /remote/path -u testuser -p secretpassword


Create a directory:


sftp-protocol client mkdir /remote/path/new_directory -u testuser -i my_sftp_key
	`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sftp-protocol.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
