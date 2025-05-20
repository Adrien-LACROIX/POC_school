package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db            *sql.DB
	templates     *template.Template
	loginAttempts = make(map[string]int)
	attemptsMutex sync.Mutex
)

func main() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=yourpassword dbname=authdb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	templates = template.Must(template.ParseGlob("templates/*.html"))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/register_submit", registerSubmitHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/login_submit", loginSubmitHandler)

	fmt.Println("Serveur démarré sur http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "index.html", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func registerSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if email == "" || username == "" || password == "" || confirm == "" {
		templates.ExecuteTemplate(w, "register.html", "Tous les champs sont requis.")
		return
	}

	if password != confirm {
		templates.ExecuteTemplate(w, "register.html", "Les mots de passe ne correspondent pas.")
		return
	}

	// Vérifier si l'email ou le pseudo existe déjà
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 OR username=$2)", email, username).Scan(&exists)
	if err != nil {
		templates.ExecuteTemplate(w, "register.html", "Erreur lors de la vérification des utilisateurs existants.")
		return
	}
	if exists {
		templates.ExecuteTemplate(w, "register.html", "Email ou pseudo déjà utilisé.")
		return
	}

	// Hacher le mot de passe
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		templates.ExecuteTemplate(w, "register.html", "Erreur lors du hachage du mot de passe.")
		return
	}

	// Insérer l'utilisateur dans la base de données
	_, err = db.Exec("INSERT INTO users (email, username, password) VALUES ($1, $2, $3)", email, username, string(hashedPassword))
	if err != nil {
		templates.ExecuteTemplate(w, "register.html", "Erreur lors de l'enregistrement de l'utilisateur.")
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func loginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	attemptsMutex.Lock()
	attempts := loginAttempts[username]
	if attempts >= 3 {
		attemptsMutex.Unlock()
		http.Redirect(w, r, "/trylater", http.StatusSeeOther)
		return
	}
	attemptsMutex.Unlock()

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username=$1", username).Scan(&hashedPassword)
	if err != nil {
		attemptsMutex.Lock()
		loginAttempts[username]++
		attemptsMutex.Unlock()
		templates.ExecuteTemplate(w, "login.html", "Nom d'utilisateur ou mot de passe incorrect.")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		attemptsMutex.Lock()
		loginAttempts[username]++
		attemptsMutex.Unlock()
		templates.ExecuteTemplate(w, "login.html", "Nom d'utilisateur ou mot de passe incorrect.")
		return
	}

	// Réinitialiser les tentatives après une connexion réussie
	attemptsMutex.Lock()
	loginAttempts[username] = 0
	attemptsMutex.Unlock()

	templates.ExecuteTemplate(w, "welcome.html", username)
}
