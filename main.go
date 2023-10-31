package main

import (
	"net/http"
	"text/template"
	"fmt"
	"time"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var tokenAuth *jwtauth.JWTAuth

func init() {
  tokenAuth = jwtauth.New("HS256", []byte("secret"), nil) // replace with secret key

  // For debugging/example purposes, we generate and print
  // a sample jwt token with claims `user_id:123` here:
  _, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"user_id": 123})
  fmt.Printf("DEBUG: a sample jwt is %s\n\n", tokenString)
}

func index(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("./view/base.html", "./view/index.html")

	tmpl.Execute(w, nil)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("./view/base.html", "./view/dashboard.html")

	tmpl.Execute(w, nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("./view/base.html", "./view/login.html")

	tmpl.Execute(w, nil)
}

func LoggedInRedirector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	  token, _, _ := jwtauth.FromContext(r.Context())
  
	  if token != nil && jwt.Validate(token) == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	  }
  
	  next.ServeHTTP(w, r)
	})
  }
  
  func UnloggedInRedirector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	  token, _, _ := jwtauth.FromContext(r.Context())
  
	  if token == nil || jwt.Validate(token) != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
	  }
  
	  next.ServeHTTP(w, r)
	})
  }
  
  func MakeToken(name string) string {
	_, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"username": name})
	return tokenString
  }

func main(){
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", index)

	r.Group(func(router chi.Router){
        router.Use(jwtauth.Verifier(tokenAuth))

        router.Use(LoggedInRedirector)

        router.Get("/login", login)
    })
    r.Group(func(router chi.Router){
        router.Use(jwtauth.Verifier(tokenAuth))

        router.Use(UnloggedInRedirector)

        router.Get("/dashboard", dashboard)
    })

    r.Group(func(r chi.Router) {
        r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
            r.ParseForm()
            userName := r.PostForm.Get("username")
            userPassword := r.PostForm.Get("password")

            if userName == "" || userPassword == "" {
              http.Error(w, "Missing username or password.", http.StatusBadRequest)
              return
            }

            token := MakeToken(userName)

            http.SetCookie(w, &http.Cookie{
                HttpOnly: true,
                Expires: time.Now().Add(5 * time.Minute),
                SameSite: http.SameSiteLaxMode,
                // Uncomment below for HTTPS:
                // Secure: true,
                Name:  "jwt", // Must be named "jwt" or else the token cannot be searched for by jwtauth.Verifier.
                Value: token,
            })

            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        })

        r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
            http.SetCookie(w, &http.Cookie{
                HttpOnly: true,
                MaxAge: -1, // Delete the cookie.
                SameSite: http.SameSiteLaxMode,
                // Uncomment below for HTTPS:
                // Secure: true,
                Name:  "jwt",
                Value: "",
            })

            http.Redirect(w, r, "/login", http.StatusSeeOther)
        })
	})

	http.ListenAndServe(":3000", r)
}