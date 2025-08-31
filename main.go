package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"displayName"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u User) WebAuthnID() []byte {
	return u.ID
}

func (u User) WebAuthnName() string {
	return u.Name
}

func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u User) WebAuthnIcon() string {
	return ""
}

type Server struct {
	webAuthn   *webauthn.WebAuthn
	users      map[string]*User
	sessions   map[string]*webauthn.SessionData
	challenges map[string]string
	mu         sync.RWMutex
}

func NewServer() (*Server, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: "webauthn-app",                                            
		RPID:          "localhost",                                               
		RPOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000"}, 
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	return &Server{
		webAuthn:   webAuthn,
		users:      make(map[string]*User),
		sessions:   make(map[string]*webauthn.SessionData),
		challenges: make(map[string]string),
	}, nil
}

func (s *Server) RegisterStartHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	user := &User{
		ID:          []byte(username),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {

		excludeList := make([]protocol.CredentialDescriptor, len(user.WebAuthnCredentials()))
		for i, cred := range user.WebAuthnCredentials() {
			excludeList[i] = protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: cred.ID,
				Transport:    cred.Transport,
			}
		}
		credCreationOpts.CredentialExcludeList = excludeList

		requireResidentKey := false
		credCreationOpts.AuthenticatorSelection = protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			UserVerification:        protocol.VerificationRequired,
			ResidentKey:             protocol.ResidentKeyRequirementPreferred,
			RequireResidentKey:      &requireResidentKey,
		}
	}

	options, sessionData, err := s.webAuthn.BeginRegistration(user, registerOptions)
	if err != nil {
		log.Printf("Failed to begin registration: %v", err)
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.sessions[username] = sessionData
	s.challenges[username] = base64.RawURLEncoding.EncodeToString(options.Response.Challenge)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) RegisterFinishHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string                               `json:"username"`
		Data     *protocol.CredentialCreationResponse `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	sessionData, exists := s.sessions[username]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "No active registration session", http.StatusBadRequest)
		return
	}

	user := &User{
		ID:          []byte(username),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	if req.Data == nil {
		http.Error(w, "Missing credential data", http.StatusBadRequest)
		return
	}

	credentialJSON, err := json.Marshal(req.Data)
	if err != nil {
		log.Printf("Failed to marshal credential data: %v", err)
		http.Error(w, "Failed to process credential data", http.StatusBadRequest)
		return
	}

	credentialRequest, err := http.NewRequest("POST", "", strings.NewReader(string(credentialJSON)))
	if err != nil {
		log.Printf("Failed to create credential request: %v", err)
		http.Error(w, "Failed to process credential data", http.StatusBadRequest)
		return
	}
	credentialRequest.Header.Set("Content-Type", "application/json")

	credential, err := s.webAuthn.FinishRegistration(user, *sessionData, credentialRequest)
	if err != nil {
		log.Printf("Failed to finish registration: %v", err)
		http.Error(w, fmt.Sprintf("Failed to finish registration: %v", err), http.StatusBadRequest)
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	s.mu.Lock()
	s.users[username] = user
	delete(s.sessions, username)
	delete(s.challenges, username)
	s.mu.Unlock()

	response := map[string]bool{"res": true}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) LoginStartHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(false)
		return
	}

	loginOptions := func(credRequestOpts *protocol.PublicKeyCredentialRequestOptions) {
		credRequestOpts.UserVerification = protocol.VerificationPreferred
	}

	options, sessionData, err := s.webAuthn.BeginLogin(user, loginOptions)
	if err != nil {
		log.Printf("Failed to begin login: %v", err)
		http.Error(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.sessions[username] = sessionData
	s.challenges[username] = base64.RawURLEncoding.EncodeToString(options.Response.Challenge)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) LoginFinishHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string                                `json:"username"`
		Data     *protocol.CredentialAssertionResponse `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	user, userExists := s.users[username]
	sessionData, sessionExists := s.sessions[username]
	s.mu.RUnlock()

	if !userExists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(false)
		return
	}

	if !sessionExists {
		http.Error(w, "No active login session", http.StatusBadRequest)
		return
	}

	if req.Data == nil {
		http.Error(w, "Missing credential data", http.StatusBadRequest)
		return
	}

	credentialJSON, err := json.Marshal(req.Data)
	if err != nil {
		log.Printf("Failed to marshal credential data: %v", err)
		http.Error(w, "Failed to process credential data", http.StatusBadRequest)
		return
	}

	credentialRequest, err := http.NewRequest("POST", "", strings.NewReader(string(credentialJSON)))
	if err != nil {
		log.Printf("Failed to create credential request: %v", err)
		http.Error(w, "Failed to process credential data", http.StatusBadRequest)
		return
	}
	credentialRequest.Header.Set("Content-Type", "application/json")

	_, err = s.webAuthn.FinishLogin(user, *sessionData, credentialRequest)
	if err != nil {
		log.Printf("Failed to finish login: %v", err)
		http.Error(w, fmt.Sprintf("Failed to finish login: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	delete(s.sessions, username)
	delete(s.challenges, username)
	s.mu.Unlock()

	response := map[string]bool{"res": true}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateChallenge() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/start", server.RegisterStartHandler).Methods("POST")
	r.HandleFunc("/register/finish", server.RegisterFinishHandler).Methods("POST")
	r.HandleFunc("/login/start", server.LoginStartHandler).Methods("POST")
	r.HandleFunc("/login/finish", server.LoginFinishHandler).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public/")))

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
