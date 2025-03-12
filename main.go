/*
This is an example application to demonstrate parsing an ID Token.
*/
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

// API reply
type RetrieveToken struct {
	AccessToken   string           `json:"access_token"`
	Expiry        time.Time        `json:"expiry,omitempty"`
	IDTokenClaims *json.RawMessage `json:"id_token_claims"`
}

// stored state
type Tokens struct {
	IDToken oidc.IDToken
	Token   oauth2.Token
}

type States struct {
	mu     sync.Mutex
	states map[string]Tokens
}

func main() {
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	providerUrl := os.Getenv("OIDC_PROVIDER_URL")

	ctx := context.Background()

	states := States{
		states: make(map[string]Tokens),
	}

	provider, err := oidc.NewProvider(ctx, providerUrl)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		state, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		setCallbackCookie(w, r, "state", state)
		setCallbackCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	http.HandleFunc("/retrieve/", func(w http.ResponseWriter, r *http.Request) {

		re := regexp.MustCompile(`^/retrieve/([^/]*)$`)
		match := re.FindStringSubmatch(r.RequestURI)

		if match == nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		state := match[1]

		states.mu.Lock()
		tokens := states.states[state]
		states.mu.Unlock()

		resp := RetrieveToken{
			AccessToken:   tokens.Token.AccessToken,
			Expiry:        tokens.Token.Expiry,
			IDTokenClaims: new(json.RawMessage),
		}

		if err := tokens.IDToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := json.MarshalIndent(resp, "", "  ")

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(data)
		log.Printf("succesfully retrieved %s", state)

	})
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		log.Printf("succesfully exchanged code for valid tokens iss=%s aud=%s sub=%s", idToken.Issuer, idToken.Audience, idToken.Subject)

		states.mu.Lock()
		states.states[state.Value] = Tokens{
			IDToken: *idToken,
			Token:   *oauth2Token,
		}
		states.mu.Unlock()

		http.Redirect(w, r, "http://127.0.0.1:5556/retrieve/"+state.Value, http.StatusFound)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
