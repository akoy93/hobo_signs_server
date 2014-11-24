package main

import (
  "encoding/json"
  "database/sql"
  "fmt"
  "github.com/dchest/uniuri"
  _ "github.com/lib/pq"
  "golang.org/x/crypto/bcrypt"
  "io"
  "log"
  "net/http"
  "os"
  "sync"
)

const (
  USERNAME_MAX_LENGTH int = 20
  PASSWORD_MAX_LENGTH int = 20
  ACCESS_TOKEN_LENGTH int = 32
  IMAGE_NAME_LENGTH int = 32
  IMAGE_DIRECTORY string = "images"
  IMAGE_EXTENSION string = "jpg"
  IMAGE_CONTENT_TYPE string = "image/jpeg"
)

// DB Schema:
// - Users: | username | password_hash |
// - Posts: | 
var db *sql.DB
var DB_USER, DB_PASSWORD, DB_NAME string

// To scale, we would use something like Redis for this
var access_tokens map[string]string // username -> access_token
var users map[string]string // access_token -> username
var mutex *sync.Mutex

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
  mutex = new(sync.Mutex)
}

func setupDB() *sql.DB {
  db, err := sql.Open("postgres", fmt.Sprintf(
    "dbname=%s user=%s password=%s sslmode=disable", 
    DB_NAME, DB_USER, DB_PASSWORD))
  LogErr(err)
  return db
}

func LogErr(err error) bool {
  if err != nil {
    log.Println(err)
  }
  return err != nil
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
  LogErr(err)
  if rows.Next() {
    respond(res, false, nil, "The username already exists.")
  } else {
    password_hash, bcrypt_err := bcrypt.GenerateFromPassword([]byte(password), 10)
    LogErr(bcrypt_err)

    _, db_err := db.Exec("INSERT INTO Users (username, password_hash) VALUES ($1, $2)", 
      username, string(password_hash))
    LogErr(db_err)

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
  LogErr(db_err)

  // Check if username exists
  if !rows.Next() {
    respond(res, false, nil, "The supplied username does not exist.")
    return
  }

  // Check if username and password match
  // Usernames should be guaranteed to be unique, so we only look at one row
  var password_hash string
  row_err := rows.Scan(&password_hash)
  LogErr(row_err)

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
    mutex.Lock()
    delete(users, access_token)
    delete(access_tokens, username)
    mutex.Unlock()
    respond(res, true, nil, nil)
  } else {
    respond(res, false, nil, "Invalid access token.")
  }
}

func isLoggedIn(res http.ResponseWriter, req *http.Request) {
  query := req.URL.Query()
  access_token := query.Get("access_token")

  if len(access_token) == 0 {
    respond(res, false, nil, "Missing field(s). Requires access_token.")
    return
  }

  if validAccessToken(access_token) {
    respond(res, true, true, nil)
  } else {
    respond(res, true, false, nil)
  }
}

func uploadImage(res http.ResponseWriter, req *http.Request) {
  file, header, file_err := req.FormFile("image")
  if LogErr(file_err) {
    respond(res, false, nil, "Did not receive file. Field name should be image.")
    return
  }
  defer file.Close()

  if header.Header["Content-Type"][0] != IMAGE_CONTENT_TYPE {
    log.Println(header.Header)
    respond(res, false, nil, fmt.Sprintf("Content-Type must be %s.", IMAGE_CONTENT_TYPE))
    return
  }

  image_name := uniuri.NewLen(IMAGE_NAME_LENGTH)
  out, os_err := os.Create(
    fmt.Sprintf("%s/%s.%s", IMAGE_DIRECTORY, image_name, IMAGE_EXTENSION))
  if LogErr(os_err) {
    respond(res, false, nil, "Unable to store image.")
    return
  }
  defer out.Close()

  _, copy_err := io.Copy(out, file)
  if LogErr(copy_err) {
    respond(res, false, nil, "Unable to copy image.")
    return
  }

  respond(res, true, image_name, nil)
}

func serveImage(res http.ResponseWriter, req *http.Request) {
  http.ServeFile(res, req, fmt.Sprintf("%s.%s", req.URL.Path[1:], IMAGE_EXTENSION))
}

// Latitude, Longitude, Caption, Image, Username
func addPost(res http.ResponseWriter, req *http.Request) {
  fields := []string{"latitude", "longitude", "access_token", "caption", "image_id"}

  if !fieldsExist(req, fields) {
    respond(res, false, nil, 
      "Missing field(s). Requires latitude, longitude, access_token, caption, image_id.")
    return
  } 

  latitude := req.Form.Get("latitude")
  longitude := req.Form.Get("longitude")
  access_token := req.Form.Get("access_token")
  caption := req.Form.Get("caption")
  image_id := req.Form.Get("image_id")

  if !validAccessToken(access_token) {
    respond(res, false, nil, "Invalid access_token. You may need to login again.")
    return
  }

  username := users[access_token]

  if !imageExists(image_id) {
    respond(res, false, nil, "Invalid image_id. The specified image does not exist.")
    return
  }

  // TODO check caption length

  query_string := "INSERT INTO Posts (location, caption, owner, image_id) " +
    "VALUES (ST_GeographyFromText('SRID=4326;POINT(" + longitude + " " + 
    latitude + fmt.Sprintf(")'), '%s', '%s', '%s')", caption, username, image_id)
  _, db_err := db.Exec(query_string)

  if LogErr(db_err) {
    respond(res, false, nil, "Error adding post to database.")
    return
  }

  respond(res, true, nil, nil)
}

func generateNewAccessToken(username string) string {
  access_token := uniuri.NewLen(ACCESS_TOKEN_LENGTH)

  mutex.Lock()
  access_tokens[username] = access_token
  users[access_token] = username
  mutex.Unlock()

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

func validAccessToken(access_token string) bool {
  var token string
  var userExists bool
  mutex.Lock()
  user, tokenExists := users[access_token]
  if tokenExists {
    token, userExists = access_tokens[user];
  }
  mutex.Unlock()

  return tokenExists && userExists && token == access_token
}

func imageExists(image_id string) bool {
  _, err := os.Stat(fmt.Sprintf("%s/%s.%s", IMAGE_DIRECTORY, image_id, IMAGE_EXTENSION))
  return !LogErr(err)
}

func respond(body http.ResponseWriter, succ bool, res interface{}, err interface{}) {
  resMap := map[string]interface{}{
    "success": succ,
    "response": res,
    "error": err,
  }
  js, json_err := json.Marshal(resMap)
  LogErr(json_err)
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
  http.HandleFunc("/upload_image", uploadImage)
  http.HandleFunc(fmt.Sprintf("/%s/", IMAGE_DIRECTORY), serveImage)
  http.HandleFunc("/add_post", addPost)
  http.ListenAndServe(":9000", nil)
}