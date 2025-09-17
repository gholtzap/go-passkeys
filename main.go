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
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
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
	webAuthn        *webauthn.WebAuthn
	users           map[string]*User
	sessions        map[string]*webauthn.SessionData
	challenges      map[string]string
	refreshSessions map[string]*webauthn.SessionData
	jwtSecret       []byte
	mu              sync.RWMutex
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func NewServer() (*Server, error) {
	jwtSecret := make([]byte, 32)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	return &Server{
		webAuthn:        nil,
		users:           make(map[string]*User),
		sessions:        make(map[string]*webauthn.SessionData),
		challenges:      make(map[string]string),
		refreshSessions: make(map[string]*webauthn.SessionData),
		jwtSecret:       jwtSecret,
	}, nil
}

func (s *Server) getWebAuthnForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	if s.webAuthn != nil {
		return s.webAuthn, nil
	}

	host := r.Host

	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	rpid := os.Getenv("WEBAUTHN_RPID")
	if rpid == "" {
		if strings.Contains(host, ":") {
			rpid = strings.Split(host, ":")[0]
		} else {
			rpid = host
		}
	}

	scheme := "http"
	if r.TLS != nil ||
		r.Header.Get("X-Forwarded-Proto") == "https" ||
		r.Header.Get("X-Forwarded-Ssl") == "on" ||
		r.Header.Get("X-Forwarded-Scheme") == "https" {
		scheme = "https"
	}

	origin := os.Getenv("WEBAUTHN_ORIGIN")
	if origin == "" {
		origin = fmt.Sprintf("%s://%s", scheme, host)
	}

	log.Printf("WebAuthn Config - RPID: %s, Origin: %s, Host: %s, Proto: %s",
		rpid, origin, r.Host, r.Header.Get("X-Forwarded-Proto"))

	wconfig := &webauthn.Config{
		RPDisplayName: "webauthn-app",
		RPID:          rpid,
		RPOrigins:     []string{origin},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	s.webAuthn = webAuthn
	return webAuthn, nil
}

func (s *Server) generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(30 * time.Second)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *Server) validateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (s *Server) jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		claims, err := s.validateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		r.Header.Set("username", claims.Username)
		next.ServeHTTP(w, r)
	}
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
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

	options, sessionData, err := webAuthn.BeginRegistration(user, registerOptions)
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, *sessionData, credentialRequest)
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

	accessToken, err := s.generateJWT(username)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   30,
	}
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
		return
	}

	loginOptions := func(credRequestOpts *protocol.PublicKeyCredentialRequestOptions) {
		credRequestOpts.UserVerification = protocol.VerificationPreferred
	}

	options, sessionData, err := webAuthn.BeginLogin(user, loginOptions)
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
		return
	}

	_, err = webAuthn.FinishLogin(user, *sessionData, credentialRequest)
	if err != nil {
		log.Printf("Failed to finish login: %v", err)
		http.Error(w, fmt.Sprintf("Failed to finish login: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	delete(s.sessions, username)
	delete(s.challenges, username)
	s.mu.Unlock()

	accessToken, err := s.generateJWT(username)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   30,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) RefreshStartHandler(w http.ResponseWriter, r *http.Request) {
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
		return
	}

	loginOptions := func(credRequestOpts *protocol.PublicKeyCredentialRequestOptions) {
		credRequestOpts.UserVerification = protocol.VerificationPreferred
	}

	options, sessionData, err := webAuthn.BeginLogin(user, loginOptions)
	if err != nil {
		log.Printf("Failed to begin token refresh: %v", err)
		http.Error(w, "Failed to begin token refresh", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.refreshSessions[username] = sessionData
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) RefreshFinishHandler(w http.ResponseWriter, r *http.Request) {
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
	sessionData, sessionExists := s.refreshSessions[username]
	s.mu.RUnlock()

	if !userExists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(false)
		return
	}

	if !sessionExists {
		http.Error(w, "No active refresh session", http.StatusBadRequest)
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

	webAuthn, err := s.getWebAuthnForRequest(r)
	if err != nil {
		log.Printf("Failed to get WebAuthn instance: %v", err)
		http.Error(w, "WebAuthn configuration error", http.StatusInternalServerError)
		return
	}

	_, err = webAuthn.FinishLogin(user, *sessionData, credentialRequest)
	if err != nil {
		log.Printf("Failed to finish token refresh: %v", err)
		http.Error(w, fmt.Sprintf("Failed to finish token refresh: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	delete(s.refreshSessions, username)
	s.mu.Unlock()

	accessToken, err := s.generateJWT(username)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   30,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("username")

	response := map[string]interface{}{
		"message": "Access granted to protected resource",
		"user":    username,
		"time":    time.Now().Format(time.RFC3339),
	}

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
	// Set Railway-specific environment variables if not already set
	if os.Getenv("WEBAUTHN_RPID") == "" && os.Getenv("RAILWAY_ENVIRONMENT") != "" {
		if railwayDomain := os.Getenv("RAILWAY_PUBLIC_DOMAIN"); railwayDomain != "" {
			os.Setenv("WEBAUTHN_RPID", railwayDomain)
			os.Setenv("WEBAUTHN_ORIGIN", "https://"+railwayDomain)
			log.Printf("Set Railway config - RPID: %s, Origin: %s", railwayDomain, "https://"+railwayDomain)
		}
	}

	if os.Getenv("WEBAUTHN_RPID") == "" {
		if port := os.Getenv("PORT"); port != "" {
			os.Setenv("WEBAUTHN_RPID", "go-passkeys-production.up.railway.app")
			os.Setenv("WEBAUTHN_ORIGIN", "https://go-passkeys-production.up.railway.app")
			log.Printf("Set fallback Railway config for go-passkeys-production.up.railway.app")
		}
	}

	server, err := NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/start", server.RegisterStartHandler).Methods("POST")
	r.HandleFunc("/register/finish", server.RegisterFinishHandler).Methods("POST")
	r.HandleFunc("/login/start", server.LoginStartHandler).Methods("POST")
	r.HandleFunc("/login/finish", server.LoginFinishHandler).Methods("POST")
	r.HandleFunc("/refresh/start", server.RefreshStartHandler).Methods("POST")
	r.HandleFunc("/refresh/finish", server.RefreshFinishHandler).Methods("POST")
	r.HandleFunc("/protected", server.jwtMiddleware(server.ProtectedHandler)).Methods("GET")

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
