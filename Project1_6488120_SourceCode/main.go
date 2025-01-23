package main

import (
    "database/sql"
    "encoding/base64"
    "fmt"
    "html/template"
    "io"
    "log"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "sync"
    "time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/crypto/bcrypt"
)

// File struct to store file info including expiration time and uploader
type File struct {
	Name       string
	Path       string
	Size       int64
	UploadedAt time.Time
	ExpiresAt  time.Time // File expiration time
	Uploader   string    // Username of the uploader
}

// Allowed file extensions
var allowedFileTypes = []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx", ".xlsx"}

// Server struct to manage file operations using channels
type Server struct {
	wg         sync.WaitGroup
	shutdown   chan struct{}
	fileChan   chan File
	deleteChan chan string
	db         *sql.DB // Add a database field
}

// Initialize and connect to the database
func initDB() (*sql.DB, error) {
	connStr := "host=localhost user=postgres password=secret dbname=gopgtest port=5432 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err // Return the error if connection fails
	}

	// Test the connection to the database
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	fmt.Println("Successfully connected to the database!") // Log success message
	return db, nil
}
/*
// Test the database connection
func testDBConnection(db *sql.DB) {
	var currentTime string
	err := db.QueryRow("SELECT NOW()").Scan(&currentTime)
	if err != nil {
		log.Fatalf("Database query failed: %v", err)
	}
	fmt.Printf("Current time from database: %s\n", currentTime)
}*/

// Create the necessary tables
func createTables(db *sql.DB) {
	usersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    );`

	filesTable := `
    CREATE TABLE IF NOT EXISTS files (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        path VARCHAR(255) NOT NULL,
        size INT NOT NULL,
        uploaded_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        uploader_id INT REFERENCES users(id)
    );`

	_, err := db.Exec(usersTable)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(filesTable)
	if err != nil {
		log.Fatal(err)
	}
}

// HTML templates
var tmpl = template.Must(template.ParseFiles("templates/index.html"))
var loginTmpl = template.Must(template.ParseFiles("templates/login.html"))   // Login template
var signupTmpl = template.Must(template.ParseFiles("templates/signup.html")) // Signup template

// Store logged-in users' names for session-like behavior
var currentUsers = map[string]string{} // map[ip_address]username

func main() {
	// Initialize the database
	db, err := initDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close() // Ensure the database connection is closed when done

	// Test the database connection
	// testDBConnection(db)

	// Create tables
	createTables(db)

	// Create server and initialize channels
	s := &Server{
		shutdown:   make(chan struct{}),
		fileChan:   make(chan File),
		deleteChan: make(chan string),
		db:         db, // Store the database connection in the server struct
	}

	// Create the uploads directory if not exists
	os.Mkdir("uploads", os.ModePerm)

	// Run the server's file manager in a separate goroutine
	go s.fileManager()

	// HTTP Handlers
	http.HandleFunc("/", basicAuth(s,s.handleFileSharing)) // Handle login/signup selection page
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(s, w, r) // Pass the server instance
	})

	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		handleSignUp(s, w, r) // Pass the server instance
	})
	http.HandleFunc("/files", basicAuth(s,s.handleFileSharing)) // Protected file sharing page
	http.HandleFunc("/upload", basicAuth(s,s.handleUpload))     // Protected upload
	http.HandleFunc("/download", basicAuth(s,s.handleDownload)) // Protected download
	http.HandleFunc("/delete", basicAuth(s,s.handleDelete))     // Protected delete

	// Static files (CSS, etc.)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start the server
	fmt.Println("Server started at http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// BasicAuth is a middleware function that checks if the user is authenticated
func basicAuth(s *Server, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Check for the username cookie
        cookie, err := r.Cookie("username")
        if err != nil || cookie.Value == "" {
            // If the cookie does not exist, redirect to login
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        // Check if the user exists in the database
        var username string
        err = s.db.QueryRow("SELECT username FROM users WHERE username = $1", cookie.Value).Scan(&username)
        if err != nil {
            // If user does not exist, redirect to login
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        // Call the next handler if the user is authenticated
        next(w, r)
    }
}


// FileManager function to handle file-related tasks, like cleanup
func (s *Server) fileManager() {
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.removeExpiredFiles() // Call the function to remove expired files
		case <-s.shutdown: // Optionally handle shutdown signals
			return
		}
	}
}

// Function to remove expired files from the database and filesystem
func (s *Server) removeExpiredFiles() {
	// Delete expired files from the database
	_, err := s.db.Exec("DELETE FROM files WHERE expires_at < NOW()")
	if err != nil {
		log.Println("Error deleting expired files from database:", err)
	}

	// Optionally, delete files from the filesystem as well
	rows, err := s.db.Query("SELECT path FROM files WHERE expires_at < NOW()")
	if err != nil {
		log.Println("Error querying for expired files:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var filePath string
		if err := rows.Scan(&filePath); err != nil {
			log.Println("Error scanning file path:", err)
			continue
		}

		// Remove the file from the filesystem
		if err := os.Remove(filePath); err != nil {
			log.Println("Error removing file:", err)
		}
	}
}

// Handle user login
func handleLogin(s *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// Retrieve the user from the database
		var hashedPassword string
		err = s.db.QueryRow("SELECT password FROM users WHERE username = $1", username).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			} else {
				http.Error(w, "Unable to query database", http.StatusInternalServerError)
			}
			return
		}

		// Compare the hashed password with the provided password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Set a cookie for the logged-in user
		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: username,
			Path:  "/",
			// Set MaxAge to 1 hour (3600 seconds) or any duration you prefer
			MaxAge:   3600,
			HttpOnly: true,  // Prevent JavaScript access to the cookie
			Secure:   false, // Set to true if using HTTPS
		})

		// Redirect to file-sharing page (or another page after successful login)
		http.Redirect(w, r, "/files", http.StatusSeeOther)
	} else {
		// Render login form
		err := loginTmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, "Unable to render login page", http.StatusInternalServerError)
		}
	}
}

// Handle user signup
func handleSignUp(s *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Unable to hash password", http.StatusInternalServerError)
			return
		}

		// Insert new user into the database
		err = insertUser(s.db, username, hashedPassword)
		if err != nil {
			if err.Error() == "pq: duplicate key value violates unique constraint \"users_username_key\"" {
				// Render signup form with error message
				signupTmpl.Execute(w, map[string]interface{}{
					"Error": "This username is already taken. Please choose a different one.",
				})
				return
			} else {
				http.Error(w, "Unable to create user", http.StatusInternalServerError)
				return
			}
		}

		// Redirect to login page after successful signup
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		// Render signup form
		err := signupTmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, "Unable to render signup page", http.StatusInternalServerError)
		}
	}
}

// Insert user into the database
func insertUser(db *sql.DB, username string, hashedPassword []byte) error {
	query := `
    INSERT INTO users (username, password)
    VALUES ($1, $2)`

	_, err := db.Exec(query, username, hashedPassword)
	return err
}

// Handle file sharing page
func (s *Server) handleFileSharing(w http.ResponseWriter, r *http.Request) {
	// Retrieve the username from the cookie
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := cookie.Value

	// Retrieve files from the database (you need to implement this)
	files, err := s.getFiles() // This function should return a slice of File structs
	if err != nil {
		http.Error(w, "Unable to retrieve files", http.StatusInternalServerError)
		return
	}

	// Render the index template with user data and file list
	err = tmpl.Execute(w, map[string]interface{}{
		"Username": username,
		"Files":    files,
	})
	if err != nil {
		http.Error(w, "Unable to render file sharing page", http.StatusInternalServerError)
	}
}

// Function to get files from the database
func (s *Server) getFiles() ([]File, error) {
	var files []File

	rows, err := s.db.Query("SELECT name, path, size, uploaded_at, uploader_id FROM files")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var file File
		var uploaderID int
		if err := rows.Scan(&file.Name, &file.Path, &file.Size, &file.UploadedAt, &uploaderID); err != nil {
			return nil, err
		}

		// Get uploader's username
		var uploader string
		err = s.db.QueryRow("SELECT username FROM users WHERE id = $1", uploaderID).Scan(&uploader)
		if err == nil {
			file.Uploader = uploader
		}

		files = append(files, file)
	}

	return files, nil
}

// Handle file upload
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var wg sync.WaitGroup
		
		// Parse the multipart form
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Get multiple files from the request
		files := r.MultipartForm.File["files"] // Change to handle multiple files

		for _, header := range files {
			wg.Add(1) // Increment the WaitGroup counter

			go func(header *multipart.FileHeader) {
				defer wg.Done() // Decrement the counter when the goroutine completes

				file, err := header.Open() // Open the uploaded file
				if err != nil {
					log.Println("Error opening file:", err)
					return
				}
				defer file.Close()

				// Validate the file extension
				if !isAllowedFileType(header.Filename) {
					log.Println("Invalid file type for:", header.Filename)
					return
				}

				// Create a path for the uploaded file
				uniqueFileName := filepath.Base(header.Filename)

				// Read the file content
				fileContent, err := io.ReadAll(file)
				if err != nil {
					log.Println("Unable to read file:", err)
					return
				}

				// Base64 encode the file content
				encodedContent := base64.StdEncoding.EncodeToString(fileContent)

				// Save the encoded content to the server
				filePath := filepath.Join("uploads", uniqueFileName)
				out, err := os.Create(filePath)
				if err != nil {
					log.Println("Unable to save file:", err)
					return
				}
				defer out.Close()

				// Write the encoded content to the file
				if _, err := out.WriteString(encodedContent); err != nil {
					log.Println("Unable to save encoded file:", err)
					return
				}

				// Set expiration to 7 days from now
				expirationTime := time.Now().Add(7 * 24 * time.Hour)

				// Insert file metadata into the database
				cookie, err := r.Cookie("username") // Get the cookie and error
				if err != nil {
					log.Println("Cookie not found:", err)
					return
				}
				username := cookie.Value

				fileInfo := File{
					Name:       uniqueFileName,
					Path:       filePath,
					Size:       int64(len(encodedContent)), // Store size of the encoded content
					UploadedAt: time.Now(),
					ExpiresAt:  expirationTime,
					Uploader:   username,
				}

				// Insert file into the database using the Server method
				err = s.insertFile(fileInfo, username)
				if err != nil {
					log.Println("Error inserting file info:", err) // Log the detailed error
					return
				}
			}(header)
		}

		wg.Wait() // Wait for all uploads to complete

		// Redirect to the file sharing page
		http.Redirect(w, r, "/files", http.StatusSeeOther)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}


// Function to check if the file type is allowed
func isAllowedFileType(filename string) bool {
	extension := filepath.Ext(filename)
	for _, allowed := range allowedFileTypes {
		if allowed == extension {
			return true
		}
	}
	return false
}

// Insert file into the database
func (s *Server) insertFile(file File, uploader string) error {
	var uploaderID int
	// Get uploader ID
	err := s.db.QueryRow("SELECT id FROM users WHERE username = $1", uploader).Scan(&uploaderID)
	if err != nil {
		return fmt.Errorf("failed to get uploader ID: %v", err)
	}

	query := `
    INSERT INTO files (name, path, size, uploaded_at, expires_at, uploader_id)
    VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = s.db.Exec(query, file.Name, file.Path, file.Size, file.UploadedAt, file.ExpiresAt, uploaderID)
	if err != nil {
		return fmt.Errorf("failed to insert file info: %v", err)
	}

	return nil
}

// Handle file download
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Get the filename from the query parameters
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Retrieve the file info from the database
	var fileInfo File
	err := s.db.QueryRow("SELECT name, path, size, uploaded_at, expires_at FROM files WHERE name = $1", filename).Scan(
		&fileInfo.Name, &fileInfo.Path, &fileInfo.Size, &fileInfo.UploadedAt, &fileInfo.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error retrieving file info", http.StatusInternalServerError)
		}
		return
	}

	// Check if the file is expired
	if time.Now().After(fileInfo.ExpiresAt) {
		http.Error(w, "File has expired", http.StatusGone)
		return
	}

	// Read the encoded content from the file
	encodedContent, err := os.ReadFile(fileInfo.Path)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	// Base64 decode the content
	decodedContent, err := base64.StdEncoding.DecodeString(string(encodedContent))
	if err != nil {
		http.Error(w, "Error decoding file content", http.StatusInternalServerError)
		return
	}

	// Set the headers for the file download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileInfo.Name))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decodedContent)))

	// Write the decoded content to the response
	_, err = w.Write(decodedContent)
	if err != nil {
		http.Error(w, "Error sending file", http.StatusInternalServerError)
	}
}

// Handle file delete
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	// Get the filename from the query parameters
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Retrieve the file info from the database
	var filePath string
	err := s.db.QueryRow("SELECT path FROM files WHERE name = $1", filename).Scan(&filePath)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error retrieving file info", http.StatusInternalServerError)
		}
		return
	}

	// Delete the file from the filesystem
	err = os.Remove(filePath)
	if err != nil {
		http.Error(w, "Error deleting file from server", http.StatusInternalServerError)
		return
	}

	// Delete the file record from the database
	_, err = s.db.Exec("DELETE FROM files WHERE name = $1", filename)
	if err != nil {
		http.Error(w, "Error deleting file record from database", http.StatusInternalServerError)
		return
	}

	// Redirect back to the file sharing page after deletion
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}
