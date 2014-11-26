// Requires DB_USER, DB_PASSWORD, DB_NAME, AWS_ACCESS_KEY_ID, and 
// AWS_SECRET_ACCESS_KEY, and BUCKET_NAME environment variables.

package main

import (
  "bytes"
  "encoding/json"
  "database/sql"
  "fmt"
  "github.com/dchest/uniuri"
  _ "github.com/lib/pq"
  "github.com/mitchellh/goamz/aws"
  "github.com/mitchellh/goamz/s3"
  "github.com/nfnt/resize"
  "golang.org/x/crypto/bcrypt"
  "image/jpeg"
  "log"
  "net/http"
  "os"
  "strings"
  "sync"
)

const (
  USERNAME_MAX_LENGTH int = 20
  PASSWORD_MAX_LENGTH int = 20
  ACCESS_TOKEN_LENGTH int = 32
  CAPTION_MAX_LENGTH int = 256
  IMAGE_NAME_LENGTH int = 32
  MAX_IMAGE_HEIGHT uint = 1080
  MAX_IMAGE_WIDTH uint = 1080
  IMAGE_EXTENSION string = "jpg"
  IMAGE_CONTENT_TYPE string = "image/jpeg"
)

// DB Schema:
// - Users: | username | password_hash |
// - Posts: | id | location | caption | owner | image_id |
var bucket *s3.Bucket
var db *sql.DB
var DB_USER, DB_PASSWORD, DB_NAME, BUCKET_NAME string

// To scale and for persistence, we would use something like Redis for this
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

  BUCKET_NAME = os.Getenv("BUCKET_NAME")
  if BUCKET_NAME == "" {
    log.Fatal("$BUCKET_NAME not set")
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

func setupS3() {
  auth, err := aws.EnvAuth()
  if err != nil {
    log.Fatal(err)
  }
  client := s3.New(auth, aws.USEast)
  bucket = client.Bucket(BUCKET_NAME)
}

func addS3Image(name string, data []byte) error {
  return bucket.Put(name, data, IMAGE_CONTENT_TYPE, s3.BucketOwnerFull)
}

func getS3Image(name string) string {
  return bucket.URL(name)
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
  fields := extractFields("POST", res, req, "username", "password", "password_confirm")
  if fields == nil {
    return
  }

  // check username length
  if len(fields["username"]) > USERNAME_MAX_LENGTH {
    respond(res, false, nil, "The maximum username length is 20 characters.")
    return
  }

  // check password length
  if len(fields["password"]) > PASSWORD_MAX_LENGTH {
    respond(res, false, nil, "The maximum password length is 20 characters.")
    return
  }

  // verify that the supplied passwords match
  if fields["password"] != fields["password_confirm"] {
    respond(res, false, nil, "The supplied passwords don't match.")
    return
  }

  // check if username already exists, otherwise, create the user
  rows, err := db.Query("SELECT * FROM users WHERE username=$1", fields["username"])
  if LogErr(err) {
    respond(res, false, nil, "Error accessing the database.")
    return
  }
  defer rows.Close()

  if rows.Next() {
    respond(res, false, nil, "The username already exists.")
  } else {
    password_hash, bcrypt_err := bcrypt.GenerateFromPassword([]byte(fields["password"]), 10)
    if LogErr(bcrypt_err) {
      respond(res, false, nil, "Bcrypt error.")
      return
    }

    _, db_err := db.Exec("INSERT INTO Users (username, password_hash) VALUES ($1, $2)", 
      fields["username"], string(password_hash))
    if LogErr(db_err) {
      respond(res, false, nil, "Database insertion error.")
      return
    }

    access_token := generateNewAccessToken(fields["username"])
    respond(res, true, access_token, nil)
  }
}

func login(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("POST", res, req, "username", "password")
  if fields == nil {
    return
  }

  // Retrieve entry for the username
  row := db.QueryRow("SELECT password_hash FROM Users WHERE username=$1", fields["username"])

  // Check if username and password match
  var password_hash string
  if row_err := row.Scan(&password_hash); LogErr(row_err) {    
    respond(res, false, nil, "The supplied username does not exist.")
    return
  }

  // compare the supplied password and the hashed password
  bcrypt_err := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(fields["password"]))
  if bcrypt_err != nil {
    respond(res, false, nil, "Incorrect password.")
    return
  }

  access_token := generateNewAccessToken(fields["username"])
  respond(res, true, access_token, nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("POST", res, req, "access_token")
  if fields == nil {
    return
  }

  username, ok := users[fields["access_token"]]
  if ok {
    mutex.Lock()
    delete(users, fields["access_token"])
    delete(access_tokens, username)
    mutex.Unlock()
    respond(res, true, nil, nil)
  } else {
    respond(res, false, nil, "Invalid access token.")
  }
}

func isLoggedIn(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("GET", res, req, "access_token")
  if fields == nil {
    return
  }

  respond(res, true, validAccessToken(fields["access_token"]), nil)
}

// Requires multipart/form-data
func uploadImage(res http.ResponseWriter, req *http.Request) {
  access_token := req.FormValue("access_token")
  if len(access_token) == 0 {
    respond(res, false, nil, "Missing field(s). Requires access_token.")
    return
  }
  if !enforceValidAccessToken(res, access_token) {
    return
  }

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

  img, decode_err := jpeg.Decode(file)
  if LogErr(decode_err) {
    respond(res, false, nil, "Unable to decode image.")
    return
  }

  resized := resize.Thumbnail(MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT, img, resize.NearestNeighbor)

  buf := new(bytes.Buffer)
  encode_err := jpeg.Encode(buf, resized, nil)
  if LogErr(encode_err) {
    respond(res, false, nil, "Unable to encode image.")
    return
  }

  image_name := uniuri.NewLen(IMAGE_NAME_LENGTH)
  if LogErr(addS3Image(image_name, buf.Bytes())) {
    respond(res, false, nil, "Unable to store image.")
    return
  }

  respond(res, true, getS3Image(image_name), nil)
}

// Latitude, Longitude, Caption, Image, Username
func addPost(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("POST", res, req, "latitude", "longitude", "access_token", "caption", "image_id")
  if fields == nil {
    return
  }

  if !enforceValidAccessToken(res, fields["access_token"]) {
    return
  }
  username := users[fields["access_token"]]

  if len(fields["caption"]) > CAPTION_MAX_LENGTH {
    respond(res, false, nil, 
      fmt.Sprintf("Invalid caption. The maximum length is %s characters.", CAPTION_MAX_LENGTH))
    return
  }

  query_string := "INSERT INTO Posts (location, caption, owner, image_id) " +
    "VALUES (ST_GeographyFromText('SRID=4326;POINT(" + fields["longitude"] + " " + 
    fields["latitude"] + fmt.Sprintf(")'), '%s', '%s', '%s')", 
    fields["caption"], username, fields["image_id"])
  _, db_err := db.Exec(query_string)

  if LogErr(db_err) {
    respond(res, false, nil, "Error adding post to database.")
    return
  }

  respond(res, true, nil, nil)
}

// requires radius to be in meters
func getPosts(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("GET", res, req, "latitude", "longitude", "radius", "access_token")
  if fields == nil {
    return
  }

  if !enforceValidAccessToken(res, fields["access_token"]) {
    return
  }

  query_string := "SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location))" +
    " as latitude, caption, owner, image_id FROM posts WHERE ST_DWithin(location, 'POINT(" + 
    fields["longitude"] + " " + fields["latitude"] + ")', " + fields["radius"] + ");"
  rows, db_err := db.Query(query_string)
  if LogErr(db_err) {
    respond(res, false, nil, "Error retrieving rows from database.")
    return
  }
  defer rows.Close()

  respond(res, true, rowsToPosts(rows), nil)
}

func myPosts(res http.ResponseWriter, req *http.Request) {
  fields := extractFields("GET", res, req, "access_token")
  if fields == nil {
    return
  }

  if !enforceValidAccessToken(res, fields["access_token"]) {
    return
  }

  username := users[fields["access_token"]]
  rows, db_err := db.Query("SELECT id, ST_X(ST_AsText(location)) as longitude, " +
    "ST_Y(ST_AsText(location)) as latitude, caption, owner, image_id FROM posts " +
    "WHERE owner=$1", username)
  if LogErr(db_err) {
    respond(res, false, nil, "Error retrieving rows from database.")
    return
  }
  defer rows.Close()

  respond(res, true, rowsToPosts(rows), nil)
}

func rowsToPosts(rows *sql.Rows) []map[string]string {
  var posts []map[string]string
  for rows.Next() {
    var id, longitude, latitude, caption, owner, image_id string
    rows.Scan(&id, &longitude, &latitude, &caption, &owner, &image_id)

    post := map[string]string{
      "id": id,
      "longitude": longitude,
      "latitude": latitude,
      "caption": caption,
      "owner": owner,
      "image_id": image_id,
    }

    posts = append(posts, post)
  }

  return posts
}

func extractFields(method string, res http.ResponseWriter, req *http.Request, fields ...string) map[string]string {
  req.ParseForm()
  fieldMap := map[string]string{}
  isPost := method == "POST"
  isGet := method == "GET"

  for _, field := range fields {
    var retrievedField string
    if isPost {  
      retrievedField = req.Form.Get(field)
    } else if isGet {
      retrievedField = req.URL.Query().Get(field)
    } else {
      respond(res, false, nil, "Invalid HTTP request type. Only permits POST and GET.")
      return nil
    }

    if len(retrievedField) == 0 {
      respond(res, false, nil, 
        fmt.Sprintf("Missings field(s). Requires %s.", strings.Join(fields, ", ")))
      return nil
    }
    fieldMap[field] = retrievedField
  }

  return fieldMap
}

func generateNewAccessToken(username string) string {
  access_token := uniuri.NewLen(ACCESS_TOKEN_LENGTH)

  mutex.Lock()
  access_tokens[username] = access_token
  users[access_token] = username
  mutex.Unlock()

  return access_token
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

func enforceValidAccessToken(res http.ResponseWriter, access_token string) bool {
  if !validAccessToken(access_token) {
    respond(res, false, nil, "Invalid access_token. You may need to login again.")
    return false
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
  LogErr(json_err)
  body.Header().Set("Content-Type", "application/json")
  body.Write(js)
}

func main() {
  db = setupDB()
  defer db.Close()
  setupS3()
  http.HandleFunc("/", hello)
  http.HandleFunc("/ping", alive)
  http.HandleFunc("/create_account", createAccount)
  http.HandleFunc("/login", login)
  http.HandleFunc("/logout", logout)
  http.HandleFunc("/is_logged_in", isLoggedIn)
  http.HandleFunc("/upload_image", uploadImage)
  http.HandleFunc("/add_post", addPost)
  http.HandleFunc("/get_posts", getPosts)
  http.HandleFunc("/my_posts", myPosts)
  http.ListenAndServe(":9000", nil)
}