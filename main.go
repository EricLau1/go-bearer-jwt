package main

import (
  "fmt"
  "log"
  "net/http"
  "time"
  "strings"
  "encoding/json"
  "github.com/gorilla/mux"
  "github.com/gorilla/handlers"
  jwt "github.com/dgrijalva/jwt-go"
)


func loadCors(r http.Handler) http.Handler {
  headers := handlers.AllowedHeaders([]string{"X-Request", "Content-type", "Authorization"})
  methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"})
  origins := handlers.AllowedOrigins([]string{"*"})
  return handlers.CORS(headers, methods, origins)(r)
}

func loadEndpoints() {
  r := mux.NewRouter().StrictSlash(true)
  r.HandleFunc("/", isAuthByBearerToken(handler)).Methods("GET")
  r.HandleFunc("/token", handlerToken).Methods("GET")
  log.Fatal(http.ListenAndServe(":3000", loadCors(r)))
}

func handler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-type", "application/json")
  err := json.NewEncoder(w).Encode(struct{
    Message string `json:"message"`
  }{
    Message: "Go Restful Api", 
  })
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    fmt.Fprintf(w, "%s", err.Error())
  }
}

func handlerToken(w http.ResponseWriter, r *http.Request) {
  token, err := generateJWT("nobody")
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    fmt.Fprintf(w, "%s", err.Error())
  }
  w.Header().Set("Content-type", "application/json")
  err = json.NewEncoder(w).Encode(struct{
    Token string `json:"token"`
  }{
    Token: token, 
  })
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    fmt.Fprintf(w, "%s", err.Error())
  }
}

var secretkey = []byte("mindawakebodyasleep")

func generateJWT(user string) (string, error) {
  token := jwt.New(jwt.SigningMethodHS256)
  claims := token.Claims.(jwt.MapClaims)
  claims["authorized"] = true
  claims["username"] = user // informe algum dado único do usuário que irá receber o token
  claims["exp"] = time.Now().Add(time.Minute * 60).Unix() // tempo que o token irá expirar
  return token.SignedString(secretkey)
}

func isAuthByBearerToken(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    header := r.Header.Get("Authorization")
    if header != "" {
      bearerToken := strings.Split(header, " ")
      if len(bearerToken) == 2 {
        token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token)(interface{}, error) {
          _, ok := token.Method.(*jwt.SigningMethodHMAC)
          if !ok {
            return nil, fmt.Errorf("Falha de autenticação")
          }
          return secretkey, nil
        })
        if err != nil {
          w.WriteHeader(http.StatusUnauthorized)
          w.Write([]byte("Unauthorized"))
          return
        }
        if token.Valid {
          handler(w, r)
        }
      }
    } else {
      w.WriteHeader(http.StatusUnauthorized)
      fmt.Fprintf(w, "Unauthorized")
    }
  })
}

func main() {
  fmt.Println("Api running on port :3000")
  loadEndpoints()
}
