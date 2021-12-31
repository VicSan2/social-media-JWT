package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

const (
	privKeyPath = "keys/private.pem"
	pubKeyPath  = "keys/public.pem"
	readMePath  = "README.txt"
)

var (
	pubKey                       *rsa.PublicKey
	privKey                      *rsa.PrivateKey
	pubKeyLiteral, readMeLiteral []byte
	authVisits, verifyVisits     int     = 0, 0
	encodingTime, decodingTime   float64 = 0, 0
)

type Claims struct {
	Sub string `json:"sub"`
	jwt.StandardClaims
}

func init() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	privKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)
	pubKeyLiteral = verifyBytes

	pubKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)

	readMe, err := ioutil.ReadFile(readMePath)
	fatal(err)

	readMeLiteral = readMe
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Parse JWT from cookie to return token
func verifyJWT(w http.ResponseWriter, r *http.Request) {

	verifyVisits++
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	nowStart := time.Now().UTC()
	// Parse the cookie with claims, to receive them in the custom way we defined above
	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {

		return pubKey, nil
	})
	nowEnd := time.Now().UTC()
	decodingTime = ((nowEnd.Sub(nowStart).Seconds() - decodingTime) / float64(verifyVisits)) + decodingTime
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println("verify-sig: ", err)
			w.Write([]byte(err.Error()))
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("verify-bad: ", err)
		w.Write([]byte(err.Error()))
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("verify-unauth: ", err)
		w.Write([]byte(err.Error()))
	}

	if token.Valid {

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			str := []byte(claims.Sub)

			w.Write(str)
		}

	}

}

// Request and sign a new JWT
func requestJWT(w http.ResponseWriter, r *http.Request) {

	authVisits++
	username := chi.URLParam(r, "user")

	expiry := time.Now().AddDate(0, 0, 1)

	claims := &Claims{
		username,
		jwt.StandardClaims{
			ExpiresAt: expiry.Unix(),
		},
	}

	nowStart := time.Now().UTC()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(privKey)
	if err != nil {
		fmt.Println("create: sign token: %w", err)
		return
	}

	nowEnd := time.Now().UTC()
	encodingTime = ((nowEnd.Sub(nowStart).Seconds() - encodingTime) / float64(authVisits)) + encodingTime

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: false,
		MaxAge:   int(expiry.Unix()),
	})

	w.Write(pubKeyLiteral)
}

// Returns the readme.txt file contents
func requestReadMe(w http.ResponseWriter, r *http.Request) {
	w.Write(readMeLiteral)
}

// Returns the visits to /auth and /verify followed by the encoding time, and the decoding time.
func getStats(w http.ResponseWriter, r *http.Request) {
	stats := "/auth visits: " + strconv.Itoa(authVisits) + ", " + "\n/verify visits: " + strconv.Itoa(verifyVisits) + "\nencoding average time in seconds: " + fmt.Sprintf("%f", encodingTime) + "\ndecoding average time in seconds: " + fmt.Sprintf("%f", decodingTime)
	w.Write([]byte(stats))
}

func main() {
	fmt.Println("Starting server on port :8080")

	err := http.ListenAndServe(":8080", router())
	if err != nil {
		fmt.Println("ListenAndServe:", err)
	}
}

// Chi router for http handling
func router() http.Handler {
	r := chi.NewRouter()
	// Add cors middleware
	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	r.Use(cors.Handler)
	r.Use(middleware.NoCache)

	// URL path handling
	r.Get("/verify", verifyJWT)
	r.Get("/README.txt", requestReadMe)
	r.Get("/stats", getStats)
	r.Route("/auth", func(r chi.Router) {
		r.Get("/{user}", requestJWT)
	})
	return r
}
