package sftp

import (
        "errors"
        "fmt"
        "io"
        "os"
        "path/filepath"
        "sync"
        "time"
)

// FileTransferOperation represents the type of file operation
type FileTransferOperation byte

const (
  // File operation types
        FileOperationList       FileTransferOperation = 0x01
        FileOperationUpload     FileTransferOperation = 0x02
        FileOperationDownload   FileTransferOperation = 0x03
        FileOperationRename     FileTransferOperation = 0x04
        FileOperationDelete     FileTransferOperation = 0x05
        FileOperationMkdir      FileTransferOperation = 0x06
        FileOperationStatus     FileTransferOperation = 0x07
        FileOperationAck        FileTransferOperation = 0x08
        FileOperationError      FileTransferOperation = 0xFF
)

// FileAttribute represents file metadata
type FileAttribute struct {
        Name        string    `json:"name"`
        Size        int64     `json:"size"`
        IsDirectory bool      `json:"is_directory"`
        ModTime     time.Time `json:"mod_time"`
        Mode        os.FileMode `json:"mode"`
}

// FileTransferRequest represents a request to perform a file operation
type FileTransferRequest struct {
        Operation FileTransferOperation `json:"operation"`
        Path      string                `json:"path"`
        NewPath   string                `json:"new_path,omitempty"` // For rename operations
        Offset    int64                 `json:"offset,omitempty"`   // For resume functionality
        Data      []byte                `json:"data,omitempty"`     // For upload data chunks
        ChunkSize int                   `json:"chunk_size,omitempty"` // Desired chunk size for downloads
}

// FileTransferResponse represents a response to a file operation
type FileTransferResponse struct {
        Success    bool                  `json:"success"`
        Operation  FileTransferOperation `json:"operation"`
        Message    string                `json:"message,omitempty"`
        Files      []FileAttribute       `json:"files,omitempty"`    // For directory listing
        Data       []byte                `json:"data,omitempty"`     // For download data chunks
        Offset     int64                 `json:"offset,omitempty"`   // Current offset for resume
        TotalSize  int64                 `json:"total_size,omitempty"`
        TransferID string                `json:"transfer_id,omitempty"` // For tracking transfers
}

// FileTransferManager handles file operations
type FileTransferManager struct {
        rootPath     string
        transfers    map[string]*ActiveTransfer
        transferLock sync.Mutex
        chunkSize    int
}

// ActiveTransfer tracks an ongoing file transfer
type ActiveTransfer struct {
        ID        string
        Operation FileTransferOperation
        Path      string
        File      *os.File
        Offset    int64
        TotalSize int64
        StartTime time.Time
        LastActivity time.Time
}

// NewFileTransferManager creates a new file transfer manager
func NewFileTransferManager(rootPath string) (*FileTransferManager, error) {
        // Ensure root path exists and is accessible
        info, err := os.Stat(rootPath)
        if err != nil {
                return nil, fmt.Errorf("invalid root path: %v", err)
        }

        if !info.IsDir() {
                return nil, errors.New("root path must be a directory")
        }

        return &FileTransferManager{
                rootPath:  rootPath,
                transfers: make(map[string]*ActiveTransfer),
                chunkSize: 1024 * 1024, // Default to 1MB chunks
        }, nil
}

// SetChunkSize sets the default chunk size for file transfers
func (fm *FileTransferManager) SetChunkSize(size int) {
        if size > 0 {
                fm.chunkSize = size
        }
}

// ProcessRequest handles a file transfer request
func (fm *FileTransferManager) ProcessRequest(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        switch req.Operation {
        case FileOperationList:
                return fm.handleList(req, sessionID)
        case FileOperationUpload:
                return fm.handleUpload(req, sessionID)
        case FileOperationDownload:
                return fm.handleDownload(req, sessionID)
        case FileOperationRename:
                return fm.handleRename(req, sessionID)
        case FileOperationDelete:
                return fm.handleDelete(req, sessionID)
        case FileOperationMkdir:
                return fm.handleMkdir(req, sessionID)
        case FileOperationStatus:
                return fm.handleStatus(req, sessionID)
        default:
                return &FileTransferResponse{
                        Success:   false,
                        Operation: req.Operation,
                        Message:   "Unsupported operation",
                }, nil
        }
}

// handleList returns directory contents
func (fm *FileTransferManager) handleList(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        fullPath := fm.getFullPath(req.Path)

        // Verify path exists and is a directory
        info, err := os.Stat(fullPath)
        if err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationList,
                        Message:   fmt.Sprintf("Path access error: %v", err),
                }, nil
        }

        if !info.IsDir() {
                // Return single file info if path is a file
                attr := FileAttribute{
                        Name:        filepath.Base(fullPath),
                        Size:        info.Size(),
                        IsDirectory: false,
                        ModTime:     info.ModTime(),
                        Mode:        info.Mode(),
                }

                return &FileTransferResponse{
                        Success:   true,
                        Operation: FileOperationList,
                        Files:     []FileAttribute{attr},
                }, nil
        }

        // Read directory contents
        entries, err := os.ReadDir(fullPath)
        if err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationList,
                        Message:   fmt.Sprintf("Failed to read directory: %v", err),
                }, nil
        }

        // Convert directory entries to FileAttributes
        files := make([]FileAttribute, 0, len(entries))
        for _, entry := range entries {
                info, err := entry.Info()
                if err != nil {
                        continue // Skip entries we can't stat
                }

                attr := FileAttribute{
                        Name:        entry.Name(),
                        Size:        info.Size(),
                        IsDirectory: entry.IsDir(),
                        ModTime:     info.ModTime(),
                        Mode:        info.Mode(),
                }
                files = append(files, attr)
        }

        return &FileTransferResponse{
                Success:   true,
                Operation: FileOperationList,
                Files:     files,
        }, nil
}

// handleUpload processes file upload requests
// handleUpload processes file upload requests
func (fm *FileTransferManager) handleUpload(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
    fullPath := fm.getFullPath(req.Path)
    transferID := fmt.Sprintf("up_%s_%s", sessionID, filepath.Base(fullPath))

    // Check if this is a continuation of an existing transfer
    fm.transferLock.Lock()
    transfer, exists := fm.transfers[transferID]
    fm.transferLock.Unlock()

    if !exists {
        // Start new upload
        // Ensure parent directory exists
        parentDir := filepath.Dir(fullPath)
        if err := os.MkdirAll(parentDir, 0755); err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationUpload,
                Message:   fmt.Sprintf("Failed to create directory structure: %v", err),
            }, nil
        }

        // Open or create the file with TRUNC to ensure we start fresh
        file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
        if err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationUpload,
                Message:   fmt.Sprintf("Failed to create file: %v", err),
            }, nil
        }

        // Create transfer record
        transfer = &ActiveTransfer{
            ID:          transferID,
            Operation:   FileOperationUpload,
            Path:        req.Path,
            File:        file,
            Offset:      0,
            StartTime:   time.Now(),
            LastActivity: time.Now(),
        }

        fm.transferLock.Lock()
        fm.transfers[transferID] = transfer
        fm.transferLock.Unlock()
    }

    // Update last activity time
    transfer.LastActivity = time.Now()

    // If offset is specified, seek to that position
    if req.Offset > 0 {
        if _, err := transfer.File.Seek(req.Offset, io.SeekStart); err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationUpload,
                Message:   fmt.Sprintf("Failed to seek to offset: %v", err),
                TransferID: transferID,
            }, nil
        }
    }

    // Write data chunk if provided
    if len(req.Data) > 0 {
        n, err := transfer.File.Write(req.Data)
        if err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationUpload,
                Message:   fmt.Sprintf("Write error: %v", err),
                TransferID: transferID,
                Offset:    transfer.Offset,
            }, nil
        }

        // Update offset based on where we wrote
        newOffset := req.Offset + int64(n)
        if newOffset > transfer.Offset {
            transfer.Offset = newOffset
        }

        // If wrote less than provided, report error
        if n < len(req.Data) {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationUpload,
                Message:   "Incomplete write - disk full?",
                TransferID: transferID,
                Offset:    transfer.Offset,
            }, nil
        }
    }

    // Check if this is the final chunk (indicated by zero-length data)
    if len(req.Data) == 0 {
        // Close the file and clean up
        transfer.File.Close()

        fm.transferLock.Lock()
        delete(fm.transfers, transferID)
        fm.transferLock.Unlock()

        // Get final file size
        info, err := os.Stat(fullPath)
        var fileSize int64
        if err == nil {
            fileSize = info.Size()
        }

        return &FileTransferResponse{
            Success:   true,
            Operation: FileOperationUpload,
            Message:   "Upload complete",
            TransferID: transferID,
            TotalSize: fileSize,
        }, nil
    }

    // Regular progress update
    return &FileTransferResponse{
        Success:   true,
        Operation: FileOperationUpload,
        Message:   "Chunk received",
        TransferID: transferID,
        Offset:    transfer.Offset,
    }, nil
}

// handleDownload processes file download requests
func (fm *FileTransferManager) handleDownload(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
    fullPath := fm.getFullPath(req.Path)
    transferID := fmt.Sprintf("down_%s_%s", sessionID, filepath.Base(fullPath))

    // Check if this is a continuation of an existing transfer
    fm.transferLock.Lock()
    transfer, exists := fm.transfers[transferID]
    fm.transferLock.Unlock()

    if !exists {
        // Start new download
        info, err := os.Stat(fullPath)
        if err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationDownload,
                Message:   fmt.Sprintf("File not found: %v", err),
            }, nil
        }

        if info.IsDir() {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationDownload,
                Message:   "Cannot download a directory",
            }, nil
        }

        // Open the file
        file, err := os.Open(fullPath)
        if err != nil {
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationDownload,
                Message:   fmt.Sprintf("Failed to open file: %v", err),
            }, nil
        }

        // If offset specified (resume), seek to that position
        offset := req.Offset
        if offset > 0 {
            if _, err := file.Seek(offset, io.SeekStart); err != nil {
                file.Close()
                return &FileTransferResponse{
                    Success:   false,
                    Operation: FileOperationDownload,
                    Message:   fmt.Sprintf("Failed to seek to offset: %v", err),
                }, nil
            }
        }

        // Create transfer record
        transfer = &ActiveTransfer{
            ID:          transferID,
            Operation:   FileOperationDownload,
            Path:        req.Path,
            File:        file,
            Offset:      offset,
            TotalSize:   info.Size(),
            StartTime:   time.Now(),
            LastActivity: time.Now(),
        }

        fm.transferLock.Lock()
        fm.transfers[transferID] = transfer
        fm.transferLock.Unlock()
    }

    // Update last activity time
    transfer.LastActivity = time.Now()

    // Determine chunk size
    chunkSize := fm.chunkSize
    if req.ChunkSize > 0 && req.ChunkSize < chunkSize {
        chunkSize = req.ChunkSize
    }

    // Read the next chunk
    data := make([]byte, chunkSize)
    n, err := transfer.File.Read(data)

    // Update offset
    transfer.Offset += int64(n)

    // Trim data to actual bytes read
    data = data[:n]

    if err != nil {
        // EOF or other error
        // Close the file and clean up
        transfer.File.Close()

        fm.transferLock.Lock()
        delete(fm.transfers, transferID)
        fm.transferLock.Unlock()

        if err == io.EOF {
            return &FileTransferResponse{
                Success:   true,
                Operation: FileOperationDownload,
                Message:   "Download complete",
                TransferID: transferID,
                Data:      data,
                Offset:    transfer.Offset,
                TotalSize: transfer.TotalSize,
            }, nil
        } else {
            // Other error
            return &FileTransferResponse{
                Success:   false,
                Operation: FileOperationDownload,
                Message:   fmt.Sprintf("Read error: %v", err),
                TransferID: transferID,
                Offset:    transfer.Offset,
            }, nil
        }
    }

    // Regular chunk (not EOF)
    return &FileTransferResponse{
        Success:   true,
        Operation: FileOperationDownload,
        Message:   "Chunk sent",
        TransferID: transferID,
        Data:      data,
        Offset:    transfer.Offset,
        TotalSize: transfer.TotalSize,
    }, nil
}

// handleRename renames a file or directory
func (fm *FileTransferManager) handleRename(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        if req.NewPath == "" {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationRename,
                        Message:   "New path not specified",
                }, nil
        }

        oldPath := fm.getFullPath(req.Path)
        newPath := fm.getFullPath(req.NewPath)

        // Check that old path exists
        if _, err := os.Stat(oldPath); err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationRename,
                        Message:   fmt.Sprintf("Source file not found: %v", err),
                }, nil
        }

        // Perform rename
        if err := os.Rename(oldPath, newPath); err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationRename,
                        Message:   fmt.Sprintf("Rename failed: %v", err),
                }, nil
        }

        return &FileTransferResponse{
                Success:   true,
                Operation: FileOperationRename,
                Message:   "Rename successful",
        }, nil
}

// handleDelete deletes a file or directory
func (fm *FileTransferManager) handleDelete(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        fullPath := fm.getFullPath(req.Path)

        // Check that path exists
        info, err := os.Stat(fullPath)
        if err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationDelete,
                        Message:   fmt.Sprintf("File not found: %v", err),
                }, nil
        }

        // Choose appropriate delete method
        var delErr error
        if info.IsDir() {
                delErr = os.RemoveAll(fullPath)
        } else {
                delErr = os.Remove(fullPath)
        }

        if delErr != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationDelete,
                        Message:   fmt.Sprintf("Delete failed: %v", delErr),
                }, nil
        }

        return &FileTransferResponse{
                Success:   true,
                Operation: FileOperationDelete,
                Message:   "Delete successful",
        }, nil
}

// handleMkdir creates a new directory
func (fm *FileTransferManager) handleMkdir(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        fullPath := fm.getFullPath(req.Path)

        // Create directory with parent directories if they don't exist
        if err := os.MkdirAll(fullPath, 0755); err != nil {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationMkdir,
                        Message:   fmt.Sprintf("Failed to create directory: %v", err),
                }, nil
        }

        return &FileTransferResponse{
                Success:   true,
                Operation: FileOperationMkdir,
                Message:   "Directory created",
        }, nil
}

// handleStatus checks the status of an ongoing transfer
func (fm *FileTransferManager) handleStatus(req *FileTransferRequest, sessionID string) (*FileTransferResponse, error) {
        if req.Path == "" {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationStatus,
                        Message:   "Transfer ID not specified",
                }, nil
        }

        transferID := req.Path // Using path to pass transferID

        fm.transferLock.Lock()
        transfer, exists := fm.transfers[transferID]
        fm.transferLock.Unlock()

        if !exists {
                return &FileTransferResponse{
                        Success:   false,
                        Operation: FileOperationStatus,
                        Message:   "Transfer not found",
                }, nil
        }

        return &FileTransferResponse{
                Success:    true,
                Operation:  FileOperationStatus,
                TransferID: transferID,
                Offset:     transfer.Offset,
                TotalSize:  transfer.TotalSize,
                Message:    fmt.Sprintf("Transfer active, %.2f%% complete", float64(transfer.Offset)/float64(transfer.TotalSize)*100),
        }, nil
}

// CleanupInactiveTransfers removes transfers that have been inactive for too long
func (fm *FileTransferManager) CleanupInactiveTransfers(maxInactiveTime time.Duration) {
        fm.transferLock.Lock()
        defer fm.transferLock.Unlock()

        now := time.Now()
        for id, transfer := range fm.transfers {
                if now.Sub(transfer.LastActivity) > maxInactiveTime {
                        transfer.File.Close()
                        delete(fm.transfers, id)
                }
        }
}

// getFullPath returns the absolute path within the root directory
func (fm *FileTransferManager) getFullPath(relativePath string) string {
        // Clean the path to remove ".." and such
        cleanPath := filepath.Clean("/" + relativePath)
        return filepath.Join(fm.rootPath, cleanPath)
}
