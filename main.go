package main

import (
	"html/template"
	"net/http"
	"sync"
)

var (
	validUsername = "user"
	validPassword = "pass123"
	userAttempts  = make(map[string]int)
	mutex         = &sync.Mutex{}
)

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/welcome", welcomeHandler)
	http.HandleFunc("/trylater", tryLaterHandler)

	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	mutex.Lock()
	defer mutex.Unlock()

	if userAttempts[username] >= 3 {
		http.Redirect(w, r, "/trylater", http.StatusSeeOther)
		return
	}

	if username == validUsername && password == validPassword {
		userAttempts[username] = 0 // Reset attempts
		http.Redirect(w, r, "/welcome?user="+username, http.StatusSeeOther)
	} else {
		userAttempts[username]++
		if userAttempts[username] >= 3 {
			http.Redirect(w, r, "/trylater", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	tmpl := template.Must(template.ParseFiles("templates/welcome.html"))
	tmpl.Execute(w, username)
}

func tryLaterHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/trylater.html"))
	tmpl.Execute(w, nil)
}
