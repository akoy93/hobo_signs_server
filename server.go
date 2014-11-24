package main

import (
  "encoding/json"
  "database/sql"
  "fmt"
  "github.com/dchest/uniuri"
  _ "github.com/lib/pq"
  "golang.org/x/crypto/bcrypt"
  "log"
  "net/http"
  "os"
)

const (
  USERNAME_MAX_LENGTH int = 20
  PASSWORD_MAX_LENGTH int = 20
  ACCESS_TOKEN_LENGTH int = 32
)

// DB Schema:
// - Users: | username | password_hash |
var db *sql.DB
var DB_USER, DB_PASSWORD, DB_NAME string

// To scale, we would use something like Redis for this
var access_tokens map[string]string // username -> access_token
var users map[string]string // access_token -> username

func init() {
  DB_USER = os.Getenv("DB_USER")
  if DB_USER == "" {
    log.Fatal("$DB_USER not set")
  }

  DB_PASSWORD = os.Getenv("DB_PASSWORD")
  if DB_PASSWORD == "" {
    log.Fatal("$DB_PASSWORD not set")
  }

  DB_NAME = os.Getenv("DB_NAME")
  if DB_NAME == "" {
    log.Fatal("$DB_NAME not set")
  }

  access_tokens = make(map[string]string)
  users = make(map[string]string)
}

func setupDB() *sql.DB {
  db, err := sql.Open("postgres", fmt.Sprintf(
    "dbname=%s user=%s password=%s sslmode=disable", 
    DB_NAME, DB_USER, DB_PASSWORD))
  PanicIf(err)
  return db
}

func PanicIf(err error) {
  if err != nil {
    panic(err)
  }
}

func hello(res http.ResponseWriter, req *http.Request) {
  fmt.Fprintf(res, "Hello!")
}

func alive(res http.ResponseWriter, req *http.Request) {
  respond(res, true, "The server is up and running!", nil)
}

// Requires a username and a password
func createAccount(res http.ResponseWriter, req *http.Request) {
  fields := []string{"username", "password", "password_confirm"}

  if !fieldsExist(req, fields) {
    respond(res, false, nil, 
      "Missing field(s). Requires username, password, password_confirm.")
    return
  } 

  username := req.Form.Get("username")
  password := req.Form.Get("password")
  password_confirm := req.Form.Get("password_confirm")

  // check username length
  if len(username) > USERNAME_MAX_LENGTH {
    respond(res, false, nil, "The maximum username length is 20 characters.")
    return
  }

  // check password length
  if len(password) > PASSWORD_MAX_LENGTH {
    respond(res, false, nil, "The maximum password length is 20 characters.")
    return
  }

  // verify that the supplied passwords match
  if password != password_confirm {
    respond(res, false, nil, "The supplied passwords don't match.")
    return
  }

  // check if username already exists, otherwise, create the user
  rows, err := db.Query("SELECT * FROM users WHERE username=$1", username)
  defer rows.Close()
  PanicIf(err)
  if rows.Next() {
    respond(res, false, nil, "The username already exists.")
  } else {
    password_hash, bcrypt_err := bcrypt.GenerateFromPassword([]byte(password), 10)
    PanicIf(bcrypt_err)

    _, db_err := db.Query("INSERT INTO Users (username, password_hash) VALUES ($1, $2)", 
      username, string(password_hash))
    defer rows.Close()
    PanicIf(db_err)

    access_token := generateNewAccessToken(username)
    
    respond(res, true, access_token, nil)
  }
}

func login(res http.ResponseWriter, req *http.Request) {
  fields := []string{"username", "password"}

  if !fieldsExist(req, fields) {
    respond(res, false, nil, 
      "Missing field(s). Requires username, password, password_confirm.")
    return
  } 

  username := req.Form.Get("username")
  password := req.Form.Get("password")

  // Retrieve entry for the username
  rows, db_err := db.Query(
    "SELECT password_hash FROM Users WHERE username=$1", username)
  defer rows.Close()
  PanicIf(db_err)

  // Check if username exists
  if !rows.Next() {
    respond(res, false, nil, "The supplied username does not exist.")
    return
  }

  // Check if username and password match
  // Usernames should be guaranteed to be unique, so we only look at one row
  var password_hash string
  row_err := rows.Scan(&password_hash)
  PanicIf(row_err)

  // compare the supplied password and the hashed password
  bcrypt_err := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))
  if bcrypt_err != nil {
    respond(res, false, nil, "Incorrect password.")
    return
  }

  access_token := generateNewAccessToken(username)
  respond(res, true, access_token, nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
  fields := []string{"access_token"}

  if !fieldsExist(req, fields) {
    respond(res, false, nil, "Missing field(s). Requires access_token.")
    return
  }

  access_token := req.Form.Get("access_token")
  username, ok := users[access_token]
  if ok {
    delete(users, access_token)
    delete(access_tokens, username)
    respond(res, true, nil, nil)
  } else {
    respond(res, false, nil, "Invalid access token.")
  }
}

func isLoggedIn(res http.ResponseWriter, req *http.Request) {
  fields := []string{"access_token"}

  if !fieldsExist(req, fields) {
    respond(res, false, nil, "Missing field(s). Requires access_token.")
    return
  }

  // Check if user is logged in by checking if token is valid
  access_token := req.Form.Get("access_token")
  if user, tokenExists := users[access_token]; tokenExists {
    if token, userExists := access_tokens[user]; userExists {
      if token == access_token {
        respond(res, true, true, nil)
        return
      }
    }
  }
  respond(res, true, false, nil)
}

// Latitude, Longitude, Caption, Image, Username
func addPost(res http.ResponseWriter, req *http.Request) {
  respond(res, true, nil, nil)
}

func generateNewAccessToken(username string) string {
  access_token := uniuri.NewLen(ACCESS_TOKEN_LENGTH)
  access_tokens[username] = access_token
  users[access_token] = username

  return access_token
}

func fieldsExist(req *http.Request, fields []string) bool {
  req.ParseForm()

  for _, field := range fields {
    if len(req.Form.Get(field)) == 0 {
      return false
    }
  }

  return true
}

func respond(body http.ResponseWriter, succ bool, res interface{}, err interface{}) {
  resMap := map[string]interface{}{
    "success": succ,
    "response": res,
    "error": err,
  }
  js, json_err := json.Marshal(resMap)
  PanicIf(json_err)
  body.Header().Set("Content-Type", "application/json")
  body.Write(js)
}

func main() {
  db = setupDB()
  defer db.Close()
  http.HandleFunc("/", hello)
  http.HandleFunc("/ping", alive)
  http.HandleFunc("/create_account", createAccount)
  http.HandleFunc("/login", login)
  http.HandleFunc("/logout", logout)
  http.HandleFunc("/is_logged_in", isLoggedIn)
  http.ListenAndServe(":9000", nil)
}