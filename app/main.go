package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db             *sql.DB
	keycloakClient gocloak.GoCloak
	realm          = "myrealm"
	clientID       = "myapp"
	clientSecret   = "your_client_secret"    // Remplacez par votre secret client
	keycloakURL    = "http://localhost:8081" // URL de votre serveur Keycloak
)

func main() {
	var err error
	// Connexion à la base de données PostgreSQL
	db, err = sql.Open("postgres", "user=postgres password=yourpassword dbname=myappdb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialisation du client Keycloak
	keycloakClient = gocloak.NewClient(keycloakURL)

	// Initialisation de Gin
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Routes
	router.GET("/", showIndex)
	router.GET("/register", showRegister)
	router.POST("/register", handleRegister)
	router.GET("/login", showLogin)
	router.POST("/login", handleLogin)
	router.GET("/welcome", showWelcome)
	router.GET("/try_later", showTryLater)

	// Démarrage du serveur
	router.Run(":8080")
}

// Affiche la page d'accueil
func showIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// Affiche la page d'inscription
func showRegister(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{"Error": ""})
}

// Gère l'inscription
func handleRegister(c *gin.Context) {
	email := strings.TrimSpace(c.PostForm("email"))
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")

	// Vérification des champs
	if email == "" || username == "" || password == "" || confirmPassword == "" {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"Error": "Tous les champs sont requis."})
		return
	}

	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"Error": "Les mots de passe ne correspondent pas."})
		return
	}

	// Vérification de l'unicité de l'email et du pseudo
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 OR username=$2)", email, username).Scan(&exists)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"Error": "Erreur lors de la vérification des utilisateurs."})
		return
	}
	if exists {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"Error": "Email ou pseudo déjà utilisé."})
		return
	}

	// Hachage du mot de passe
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"Error": "Erreur lors du hachage du mot de passe."})
		return
	}

	// Insertion dans la base de données
	_, err = db.Exec("INSERT INTO users (email, username, password) VALUES ($1, $2, $3)", email, username, string(hashedPassword))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"Error": "Erreur lors de l'enregistrement de l'utilisateur."})
		return
	}

	// Création de l'utilisateur dans Keycloak
	ctx := context.Background()
	token, err := keycloakClient.LoginAdmin(ctx, "admin", "admin", realm)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"Error": "Erreur lors de la connexion à Keycloak."})
		return
	}

	user := gocloak.User{
		Username:      gocloak.StringP(username),
		Email:         gocloak.StringP(email),
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(true),
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Type:      gocloak.StringP("password"),
				Value:     gocloak.StringP(password),
				Temporary: gocloak.BoolP(false),
			},
		},
	}

	_, err = keycloakClient.CreateUser(ctx, token.AccessToken, realm, user)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"Error": "Erreur lors de la création de l'utilisateur dans Keycloak."})
		return
	}

	c.Redirect(http.StatusSeeOther, "/login")
}

// Affiche la page de connexion
func showLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{"Error": ""})
}

// Gère la connexion
func handleLogin(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")

	// Vérification des champs
	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"Error": "Tous les champs sont requis."})
		return
	}

	// Vérification des tentatives de connexion
	attemptsKey := fmt.Sprintf("login_attempts_%s", username)
	attempts := getLoginAttempts(c, attemptsKey)
	if attempts >= 3 {
		c.Redirect(http.StatusSeeOther, "/try_later")
		return
	}

	// Authentification avec Keycloak
	ctx := context.Background()
	_, err := keycloakClient.Login(ctx, clientID, clientSecret, realm, username, password)
	if err != nil {
		incrementLoginAttempts(c, attemptsKey)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"Error": "Identifiants incorrects."})
		return
	}

	// Réinitialisation des tentatives de connexion
	resetLoginAttempts(c, attemptsKey)

	// Redirection vers la page de bienvenue
	c.Redirect(http.StatusSeeOther, fmt.Sprintf("/welcome?username=%s", username))
}

// Affiche la page de bienvenue
func showWelcome(c *gin.Context) {
	username := c.Query("username")
	c.HTML(http.StatusOK, "welcome.html", gin.H{"Username": username})
}

// Affiche la page "Try later"
func showTryLater(c *gin.Context) {
	c.HTML(http.StatusOK, "try_later.html", nil)
}

// Gestion des tentatives de connexion (en mémoire pour simplification)
var loginAttempts = make(map[string]int)

func getLoginAttempts(c *gin.Context, key string) int {
	return loginAttempts[key]
}

func incrementLoginAttempts(c *gin.Context, key string) {
	loginAttempts[key]++
}

func resetLoginAttempts(c *gin.Context, key string) {
	loginAttempts[key] = 0
}
