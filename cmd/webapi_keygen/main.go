// webapi_keygen generates and manages Web API keys for the RAS Web AIM API.
// Usage: go run ./cmd/webapi_keygen [command] [options]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	"github.com/mk6i/open-oscar-server/state"
)

const (
	keyLength = 32 // 256 bits of entropy
)

func main() {
	// Load environment configuration
	if err := godotenv.Load("config/settings.env"); err != nil {
		fmt.Printf("Config file not found, using environment variables\n")
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "generate", "gen":
		handleGenerate(args)
	case "list", "ls":
		handleList(args)
	case "revoke", "delete", "rm":
		handleRevoke(args)
	case "activate":
		handleActivate(args)
	case "update":
		handleUpdate(args)
	case "show":
		handleShow(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Web API Key Generator for RAS")
	fmt.Println("\nUsage: webapi_keygen <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  generate, gen     Generate a new API key")
	fmt.Println("  list, ls          List all API keys")
	fmt.Println("  show              Show details of a specific key")
	fmt.Println("  revoke, delete    Deactivate an API key")
	fmt.Println("  activate          Reactivate an API key")
	fmt.Println("  update            Update API key settings")
	fmt.Println("  help              Show this help message")
	fmt.Println("\nGenerate Options:")
	fmt.Println("  --app-name        Application name (required)")
	fmt.Println("  --origins         Comma-separated list of allowed origins")
	fmt.Println("  --rate-limit      Requests per minute (default: 60)")
	fmt.Println("  --capabilities    Comma-separated list of capabilities")
	fmt.Println("\nUpdate Options:")
	fmt.Println("  --dev-id          Developer ID to update (required)")
	fmt.Println("  --app-name        New application name")
	fmt.Println("  --origins         New comma-separated list of allowed origins")
	fmt.Println("  --rate-limit      New requests per minute limit")
	fmt.Println("  --capabilities    New comma-separated list of capabilities")
	fmt.Println("\nExamples:")
	fmt.Println("  webapi_keygen generate --app-name \"My Web Client\" --origins \"https://example.com,https://app.example.com\"")
	fmt.Println("  webapi_keygen list")
	fmt.Println("  webapi_keygen show --dev-id dev_abc123")
	fmt.Println("  webapi_keygen revoke --dev-id dev_abc123")
	fmt.Println("  webapi_keygen update --dev-id dev_abc123 --rate-limit 120")
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	appName := fs.String("app-name", "", "Application name (required)")
	originsStr := fs.String("origins", "", "Comma-separated list of allowed origins")
	rateLimit := fs.Int("rate-limit", 60, "Requests per minute")
	capabilitiesStr := fs.String("capabilities", "", "Comma-separated list of capabilities")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *appName == "" {
		fmt.Fprintln(os.Stderr, "Error: --app-name is required")
		os.Exit(1)
	}

	// Parse origins and capabilities
	var origins []string
	if *originsStr != "" {
		origins = parseCSV(*originsStr)
	}

	var capabilities []string
	if *capabilitiesStr != "" {
		capabilities = parseCSV(*capabilitiesStr)
	}

	// Generate secure random key
	keyBytes := make([]byte, keyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}
	devKey := hex.EncodeToString(keyBytes)

	// Generate dev_id
	devID := fmt.Sprintf("dev_%s", uuid.New().String())

	// Create the API key record
	apiKey := state.WebAPIKey{
		DevID:          devID,
		DevKey:         devKey,
		AppName:        *appName,
		CreatedAt:      time.Now(),
		IsActive:       true,
		RateLimit:      *rateLimit,
		AllowedOrigins: origins,
		Capabilities:   capabilities,
	}

	// Connect to database and insert the key
	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := store.CreateAPIKey(ctx, apiKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating API key: %v\n", err)
		os.Exit(1)
	}

	// Output the generated key details
	fmt.Println("Successfully generated Web API key:")
	fmt.Println("=====================================")
	fmt.Printf("Developer ID:  %s\n", devID)
	fmt.Printf("API Key:       %s\n", devKey)
	fmt.Printf("App Name:      %s\n", *appName)
	fmt.Printf("Rate Limit:    %d requests/minute\n", *rateLimit)
	if len(origins) > 0 {
		fmt.Printf("Origins:       %s\n", strings.Join(origins, ", "))
	}
	if len(capabilities) > 0 {
		fmt.Printf("Capabilities:  %s\n", strings.Join(capabilities, ", "))
	}
	fmt.Println("=====================================")
	fmt.Println("\nIMPORTANT: Save the API key securely. It cannot be retrieved later.")
}

func handleList(args []string) {
	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing API keys: %v\n", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Println("No API keys found.")
		return
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DEV ID\tAPP NAME\tACTIVE\tRATE LIMIT\tCREATED\tLAST USED")
	fmt.Fprintln(w, "------\t--------\t------\t----------\t-------\t---------")

	for _, key := range keys {
		lastUsed := "Never"
		if key.LastUsed != nil {
			lastUsed = key.LastUsed.Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%s\t%s\t%v\t%d/min\t%s\t%s\n",
			truncateString(key.DevID, 20),
			truncateString(key.AppName, 20),
			key.IsActive,
			key.RateLimit,
			key.CreatedAt.Format("2006-01-02"),
			lastUsed,
		)
	}
	w.Flush()
}

func handleShow(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	devID := fs.String("dev-id", "", "Developer ID (required)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *devID == "" {
		fmt.Fprintln(os.Stderr, "Error: --dev-id is required")
		os.Exit(1)
	}

	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	key, err := store.GetAPIKeyByDevID(ctx, *devID)
	if err != nil {
		if err == state.ErrNoAPIKey {
			fmt.Fprintf(os.Stderr, "Error: API key not found for dev_id: %s\n", *devID)
		} else {
			fmt.Fprintf(os.Stderr, "Error retrieving API key: %v\n", err)
		}
		os.Exit(1)
	}

	// Output detailed key information
	fmt.Println("Web API Key Details:")
	fmt.Println("=====================================")
	fmt.Printf("Developer ID:  %s\n", key.DevID)
	fmt.Printf("App Name:      %s\n", key.AppName)
	fmt.Printf("Active:        %v\n", key.IsActive)
	fmt.Printf("Rate Limit:    %d requests/minute\n", key.RateLimit)
	fmt.Printf("Created:       %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))
	if key.LastUsed != nil {
		fmt.Printf("Last Used:     %s\n", key.LastUsed.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("Last Used:     Never")
	}
	if len(key.AllowedOrigins) > 0 {
		fmt.Printf("Origins:       %s\n", strings.Join(key.AllowedOrigins, ", "))
	} else {
		fmt.Println("Origins:       All origins allowed")
	}
	if len(key.Capabilities) > 0 {
		fmt.Printf("Capabilities:  %s\n", strings.Join(key.Capabilities, ", "))
	} else {
		fmt.Println("Capabilities:  All capabilities enabled")
	}
	fmt.Println("=====================================")
}

func handleRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	devID := fs.String("dev-id", "", "Developer ID to revoke (required)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *devID == "" {
		fmt.Fprintln(os.Stderr, "Error: --dev-id is required")
		os.Exit(1)
	}

	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	isActive := false
	update := state.WebAPIKeyUpdate{
		IsActive: &isActive,
	}

	if err := store.UpdateAPIKey(ctx, *devID, update); err != nil {
		if err == state.ErrNoAPIKey {
			fmt.Fprintf(os.Stderr, "Error: API key not found for dev_id: %s\n", *devID)
		} else {
			fmt.Fprintf(os.Stderr, "Error revoking API key: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully revoked API key: %s\n", *devID)
}

func handleActivate(args []string) {
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	devID := fs.String("dev-id", "", "Developer ID to activate (required)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *devID == "" {
		fmt.Fprintln(os.Stderr, "Error: --dev-id is required")
		os.Exit(1)
	}

	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	isActive := true
	update := state.WebAPIKeyUpdate{
		IsActive: &isActive,
	}

	if err := store.UpdateAPIKey(ctx, *devID, update); err != nil {
		if err == state.ErrNoAPIKey {
			fmt.Fprintf(os.Stderr, "Error: API key not found for dev_id: %s\n", *devID)
		} else {
			fmt.Fprintf(os.Stderr, "Error activating API key: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully activated API key: %s\n", *devID)
}

func handleUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	devID := fs.String("dev-id", "", "Developer ID to update (required)")
	appName := fs.String("app-name", "", "New application name")
	originsStr := fs.String("origins", "", "New comma-separated list of allowed origins")
	rateLimit := fs.Int("rate-limit", -1, "New requests per minute limit")
	capabilitiesStr := fs.String("capabilities", "", "New comma-separated list of capabilities")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if *devID == "" {
		fmt.Fprintln(os.Stderr, "Error: --dev-id is required")
		os.Exit(1)
	}

	update := state.WebAPIKeyUpdate{}

	if *appName != "" {
		update.AppName = appName
	}

	if *originsStr != "" {
		origins := parseCSV(*originsStr)
		update.AllowedOrigins = &origins
	}

	if *rateLimit > 0 {
		update.RateLimit = rateLimit
	}

	if *capabilitiesStr != "" {
		capabilities := parseCSV(*capabilitiesStr)
		update.Capabilities = &capabilities
	}

	// Check if any updates were provided
	updateJSON, _ := json.Marshal(update)
	if string(updateJSON) == "{}" {
		fmt.Fprintln(os.Stderr, "Error: No update fields provided")
		os.Exit(1)
	}

	store, err := connectToStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := store.UpdateAPIKey(ctx, *devID, update); err != nil {
		if err == state.ErrNoAPIKey {
			fmt.Fprintf(os.Stderr, "Error: API key not found for dev_id: %s\n", *devID)
		} else {
			fmt.Fprintf(os.Stderr, "Error updating API key: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully updated API key: %s\n", *devID)
}

func connectToStore() (*state.SQLiteUserStore, error) {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "oscar.sqlite"
	}
	return state.NewSQLiteUserStore(dbPath)
}

func parseCSV(input string) []string {
	if input == "" {
		return []string{}
	}
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
