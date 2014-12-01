// Requires DB_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// PORT, BUCKET_NAME, and GEONAMES_USERNAME environment variables.

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dchest/uniuri"
	"github.com/jmoiron/jsonq"
	_ "github.com/lib/pq"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/s3"
	"github.com/nfnt/resize"
	"golang.org/x/crypto/bcrypt"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	USERNAME_MAX_LENGTH int    = 20
	PASSWORD_MAX_LENGTH int    = 20
	ACCESS_TOKEN_LENGTH int    = 32
	CAPTION_MAX_LENGTH  int    = 256
	IMAGE_NAME_LENGTH   int    = 32
	MAX_IMAGE_HEIGHT    uint   = 1080
	MAX_IMAGE_WIDTH     uint   = 1080
	IMAGE_EXTENSION     string = "jpg"
	IMAGE_CONTENT_TYPE  string = "image/jpeg"
	NUM_GEOCODE_RETRIES int    = 3
	CITY_API_URL        string = "http://api.geonames.org/findNearbyPostalCodesJSON?lat=%s&lng=%s&username=%s"
	PLACE_API_URL       string = "http://api.geonames.org/findNearbyPlaceNameJSON?lat=%s&lng=%s&username=%s"
)

// DB Schema:
// - Users: | username | password_hash |
// - Posts: | id | location | caption | owner | image_url | hashtags | created_at |
// - Hashtags: | hashtag | post_id |
var bucket *s3.Bucket
var db *sql.DB
var DB_URL, BUCKET_NAME, PORT, GEONAMES_USERNAME string

// To scale and for persistence, we would use something like Redis for this
var access_tokens map[string]string // username -> access_token
var users map[string]string         // access_token -> username
var mutex *sync.Mutex

type convert func(*sql.Rows) map[string]string

func init() {
	DB_URL = os.Getenv("DB_URL")
	if DB_URL == "" {
		log.Fatal("$DB_URL not set")
	}

	BUCKET_NAME = os.Getenv("BUCKET_NAME")
	if BUCKET_NAME == "" {
		log.Fatal("$BUCKET_NAME not set")
	}

	PORT = os.Getenv("PORT")
	if PORT == "" {
		log.Fatal("$PORT not set")
	}

	GEONAMES_USERNAME = os.Getenv("GEONAMES_USERNAME")
	if GEONAMES_USERNAME == "" {
		log.Fatal("$GEONAMES_USERNAME not set")
	}

	access_tokens = make(map[string]string)
	users = make(map[string]string)
	mutex = new(sync.Mutex)

	// Setup Amazon S3 connection
	auth, err := aws.EnvAuth()
	if err != nil {
		log.Fatal(err)
	}
	client := s3.New(auth, aws.USEast)
	bucket = client.Bucket(BUCKET_NAME)
}

func setupDB() *sql.DB {
	db, err := sql.Open("postgres", DB_URL)
	LogErr(err)
	return db
}

func addToS3(res http.ResponseWriter, name string, data []byte, c chan string) {
	defer close(c)
	err := bucket.Put(name, data, IMAGE_CONTENT_TYPE, s3.BucketOwnerFull)
	if LogErr(err) {
		respond(res, false, nil, "Unable to store image.")
		c <- ""
	} else {
		c <- bucket.URL(name)
	}
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
// Optional "hashtags" parameter in the form of #HASTAG1|#HASHTAG2|#HASHTAG3
func addPost(res http.ResponseWriter, req *http.Request) {
	logRequest(req);
	fields := extractFields("POST", res, req, "latitude", "longitude", "access_token", "caption")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	if len(fields["caption"]) > CAPTION_MAX_LENGTH {
		respond(res, false, nil,
			fmt.Sprintf("Invalid caption. The maximum length is %s characters.", CAPTION_MAX_LENGTH))
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

	bytes := processImage(res, file)
	if bytes == nil {
		return
	}

	// Add image to S3
	image_name := uniuri.NewLen(IMAGE_NAME_LENGTH)
	s3Chan := make(chan string)
	go addToS3(res, image_name, bytes, s3Chan)

	// Reverse geocode latitude and longitude
	geocodeChan := make(chan string)
	go reverseGeocodeRetry(fields["latitude"], fields["longitude"], NUM_GEOCODE_RETRIES, geocodeChan)

	// Extract hashtags
	hashtags := extractHashtags(fields["caption"])

	// Add to Posts table
	image_url := <-s3Chan
	if len(image_url) == 0 {
		return
	}
	location_name := <-geocodeChan
	fmt.Println(image_url)
	fmt.Println(location_name)
	username := users[fields["access_token"]]
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`INSERT INTO Posts (location, location_name, caption, owner, media_url, media_type, hashtags, created_at)
      VALUES (`+point_str+`, $1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) RETURNING id`,
		location_name, fields["caption"], username, image_url, "image", strings.Join(hashtags, "|"))

	if LogErr(db_err) {
		respond(res, false, nil, "Error adding post to database.")
		return
	}

	// Add to hashtags table
	var post_id string
	if rows.Next() {
		rows.Scan(&post_id)
	}
	for _, hashtag := range hashtags {
		_, db_err := db.Exec("INSERT INTO Hashtags (hashtag, post_id) VALUES($1, $2)", hashtag, post_id)
		if LogErr(db_err) {
			respond(res, false, nil, "Error adding hashtag to database.")
			return
		}
	}

	respond(res, true, nil, nil)
}

func extractHashtags(caption string) []string {
	r, _ := regexp.Compile(`#([\w\d]+)`)
	hashtagMatches := r.FindAllStringSubmatch(caption, -1)
	found := map[string]bool{}
	hashtags := []string{}
	for _, s := range hashtagMatches {
		hashtag := strings.ToLower(s[1])
		if _, ok := found[hashtag]; !ok {
			hashtags = append(hashtags, hashtag)
			found[hashtag] = true
		}
	}
	return hashtags
}

func processImage(res http.ResponseWriter, file io.Reader) []byte {
	img, decode_err := jpeg.Decode(file)
	if LogErr(decode_err) {
		respond(res, false, nil, "Unable to decode image.")
		return nil
	}

	resized := resize.Thumbnail(MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT, img, resize.NearestNeighbor)

	buf := new(bytes.Buffer)
	encode_err := jpeg.Encode(buf, resized, nil)
	if LogErr(encode_err) {
		respond(res, false, nil, "Unable to encode image.")
		return nil
	}

	return buf.Bytes()
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

	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location)) as latitude, 
      location_name, caption, owner, media_url, media_type, hashtags, created_at, 
      ST_DISTANCE(location, `+point_str+`) as distance 
      FROM posts WHERE ST_DWithin(location, `+point_str+`, $1)`, fields["radius"])
	if LogErr(db_err) {
		respond(res, false, nil, "Error retrieving rows from database.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, parsePost), nil)
}

func myPosts(res http.ResponseWriter, req *http.Request) {
	fields := extractFields("GET", res, req, "access_token", "latitude", "longitude")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	username := users[fields["access_token"]]
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location)) as latitude, 
      location_name, caption, owner, media_url, media_type, hashtags, created_at, 
      ST_DISTANCE(location, `+point_str+`) as distance 
      FROM posts WHERE owner=$1`, username)
	if LogErr(db_err) {
		respond(res, false, nil, "Error retrieving rows from database.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, parsePost), nil)
}

func getPostsWithHashtag(res http.ResponseWriter, req *http.Request) {
	fields := extractFields("GET", res, req, "access_token", "latitude", "longitude", "hashtag")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	hashtag := strings.ToLower(fields["hashtag"])
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location)) as latitude, 
      location_name, caption, owner, media_url, media_type, hashtags, created_at, 
      ST_DISTANCE(location, `+point_str+`) as distance 
      FROM posts p INNER JOIN (SELECT * FROM Hashtags WHERE hashtag=$1) h 
      ON h.post_id=p.id`, hashtag)
	if LogErr(db_err) {
		respond(res, false, nil, "Error retrieving rows from database.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, parsePost), nil)
}

func getHashtagsByPopularity(res http.ResponseWriter, req *http.Request) {
	fields := extractFields("GET", res, req, "access_token")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	rows, db_err := db.Query("SELECT hashtag, COUNT(*) as num_posts FROM Hashtags GROUP BY hashtag ORDER BY num_posts DESC")
	if LogErr(db_err) {
		respond(res, false, nil, "Error computing hashtag popularity. Unable to retreive rows.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, func(rows *sql.Rows) map[string]string {
		var hashtag, num_posts string
		rows.Scan(&hashtag, &num_posts)
		return map[string]string{"hashtag": hashtag, "num_posts": num_posts}
	}), nil)
}

func pointString(latitude string, longitude string) string {
	return fmt.Sprintf("ST_GeographyFromText('SRID=4326;POINT(%s %s)')", longitude, latitude)
}

func rowsToPosts(rows *sql.Rows, parse convert) []map[string]string {
	var posts []map[string]string
	for rows.Next() {
		posts = append(posts, parse(rows))
	}

	return posts
}

func parsePost(rows *sql.Rows) map[string]string {
	var id, longitude, latitude, location_name, caption, owner, media_url, media_type, hashtags string
	var created_at time.Time
	var distance float64
	rows.Scan(&id, &longitude, &latitude, &location_name, &caption, &owner,
		&media_url, &media_type, &hashtags, &created_at, &distance)

	post := map[string]string{
		"id":            id,
		"longitude":     longitude,
		"latitude":      latitude,
		"location_name": location_name,
		"caption":       caption,
		"owner":         owner,
		"media_url":     media_url,
		"media_type":    media_type,
		"hashtags":      hashtags,
		"created_at":    created_at.String(),
		"distance":      fmt.Sprintf("%.2f", distance),
	}

	return post
}

func extractFields(method string, res http.ResponseWriter, req *http.Request, fields ...string) map[string]string {
	fieldMap := map[string]string{}
	isPost := method == "POST"
	isGet := method == "GET"

	for _, field := range fields {
		var retrievedField string
		if isPost {
			retrievedField = req.FormValue(field)
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
		token, userExists = access_tokens[user]
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
		"success":  succ,
		"response": res,
		"error":    err,
	}
	js, json_err := json.Marshal(resMap)
	LogErr(json_err)
	body.Header().Set("Content-Type", "application/json")
	body.Write(js)
}

func reverseGeocodeRetry(latitude, longitude string, retry int, c chan string) {
	defer close(c)
	for i := 0; i < retry; i++ {
		location := reverseGeocode(latitude, longitude)
		if len(location) != 0 {
			c <- location
			return
		}
	}

	c <- ""
}

func reverseGeocode(latitude, longitude string) string {
	var place, city, state string
	var fetchErr bool
	var wg sync.WaitGroup

	wg.Add(2)
	go func(url string) {
		defer wg.Done()
		jq, err := getJSON(url)
		if err != nil {
			fetchErr = true
			return
		}
		cityName, cityErr := jq.String("postalCodes", "0", "placeName")
		stateName, stateErr := jq.String("postalCodes", "0", "adminCode1")
		if cityErr != nil || stateErr != nil {
			fetchErr = true
			return
		} else {
			city = cityName
			state = stateName
		}
	}(fmt.Sprintf(CITY_API_URL, latitude, longitude, GEONAMES_USERNAME))

	go func(url string) {
		defer wg.Done()
		jq, err := getJSON(url)
		if err != nil {
			fetchErr = true
			return
		}
		placeName, placeErr := jq.String("geonames", "0", "toponymName")
		if placeErr != nil {
			fetchErr = true
			return
		} else {
			place = placeName
		}
	}(fmt.Sprintf(PLACE_API_URL, latitude, longitude, GEONAMES_USERNAME))

	wg.Wait()

	if fetchErr {
		return ""
	} else {
		return place + ", " + city + ", " + state
	}
}

func getJSON(url string) (*jsonq.JsonQuery, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	r := make(map[string]interface{})
	body, _ := ioutil.ReadAll(res.Body)
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return jsonq.NewQuery(r), nil
}

func logRequest(r *http.Request) {
	log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
	log.Println(r.Header)
	r.ParseMultipartForm(1000000)
	log.Println(r.MultipartForm)
}

func main() {
	db = setupDB()
	defer db.Close()

	log.Println("Starting server on port", PORT)

	http.HandleFunc("/", hello)
	http.HandleFunc("/ping", alive)
	http.HandleFunc("/create_account", createAccount)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/is_logged_in", isLoggedIn)
	http.HandleFunc("/add_post", addPost)
	http.HandleFunc("/get_posts", getPosts)
	http.HandleFunc("/my_posts", myPosts)
	http.HandleFunc("/get_posts_with_hashtag", getPostsWithHashtag)
	http.HandleFunc("/hashtags", getHashtagsByPopularity)
	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}
