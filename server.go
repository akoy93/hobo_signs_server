// Requires DB_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// PORT, BUCKET_NAME, and GEONAMES_USERNAME environment variables.

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dchest/uniuri"
	"github.com/disintegration/imaging"
	"github.com/jmoiron/jsonq"
	_ "github.com/lib/pq"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/s3"
	"golang.org/x/crypto/bcrypt"
	"image"
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
	MEDIA_NAME_LENGTH   int    = 32
	MAX_IMAGE_HEIGHT    int    = 1920
	MAX_IMAGE_WIDTH     int    = 1080
	IMAGE_EXTENSION     string = "jpg"
	IMAGE_CONTENT_TYPE  string = "image/jpeg"
	VIDEO_CONTENT_TYPE  string = "video/mp4"
	NUM_GEOCODE_RETRIES int    = 3
	CITY_API_URL        string = "http://api.geonames.org/findNearbyPostalCodesJSON?lat=%s&lng=%s&username=%s"
	PLACE_API_URL       string = "http://api.geonames.org/findNearbyPlaceNameJSON?lat=%s&lng=%s&username=%s"
)

// DB Schema:
// - Users: | username | password_hash |
// - Posts: | id | location | caption | owner | media_url | hashtags | created_at |
// - Hashtags: | hashtag | post_id |
var bucket *s3.Bucket
var db *sql.DB
var DB_URL, BUCKET_NAME, PORT, GEONAMES_USERNAME string

// To scale and for persistence, we would use something like Redis for this
var access_tokens map[string]string // username -> access_token
var users map[string]string         // access_token -> username
var mutex *sync.Mutex

type convert func(*sql.Rows) map[string]string

// For development
var mostRecentURL string
var imageMutex *sync.Mutex

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
	imageMutex = new(sync.Mutex)

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

func addToS3(res http.ResponseWriter, name string, media_type string, data []byte, c chan string) {
	defer close(c)
	err := bucket.Put(name, data, media_type, s3.BucketOwnerFull)
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

func mostRecentImage(res http.ResponseWriter, req *http.Request) {
	http.Redirect(res, req, mostRecentURL, 301)
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

	header_str := header.Header["Content-Type"][0]

	var media_type string
	if header_str != IMAGE_CONTENT_TYPE && header_str != VIDEO_CONTENT_TYPE {
		log.Println(header.Header)
		respond(res, false, nil, fmt.Sprintf("Content-Type must be %s or %s.", IMAGE_CONTENT_TYPE, VIDEO_CONTENT_TYPE))
		return
	} else {
		media_type = header_str
	}

	bytes := processMedia(res, file, media_type)
	if bytes == nil {
		return
	}

	// Add image to S3
	media_name := uniuri.NewLen(MEDIA_NAME_LENGTH)
	s3Chan := make(chan string)
	go addToS3(res, media_name, media_type, bytes, s3Chan)

	// Reverse geocode latitude and longitude
	geocodeChan := make(chan string)
	go reverseGeocodeRetry(fields["latitude"], fields["longitude"], NUM_GEOCODE_RETRIES, geocodeChan)

	// Extract hashtags
	hashtags := extractHashtags(fields["caption"])

	// Add to Posts table
	media_url := <-s3Chan

	imageMutex.Lock()
	mostRecentURL = media_url
	imageMutex.Unlock()

	if len(media_url) == 0 {
		return
	}
	location_name := <-geocodeChan
	username := users[fields["access_token"]]
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`INSERT INTO Posts (location, location_name, caption, owner, media_url, media_type, hashtags, created_at)
      VALUES (`+point_str+`, $1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) RETURNING id`,
		location_name, fields["caption"], username, media_url, media_type, strings.Join(hashtags, "|"))

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

func processMedia(res http.ResponseWriter, file io.Reader, media_type string) []byte {
	// copy file reader
	buf, _ := ioutil.ReadAll(file)

	if media_type == VIDEO_CONTENT_TYPE {
		return buf
	}

	file = bytes.NewBuffer(buf)
	file_copy := bytes.NewBuffer(buf)

	// get image size
	img_config, _, config_err := image.DecodeConfig(file_copy)
	if LogErr(config_err) {
		respond(res, false, nil, "Unable to get image size.")
		return nil
	}

	// decode jpeg image
	img, decode_err := jpeg.Decode(file)
	if LogErr(decode_err) {
		respond(res, false, nil, "Unable to decode image.")
		return nil
	}

	// rotate image and resize if necessary
	if img_config.Width > img_config.Height {
		img = imaging.Rotate270(img)
	}
	if img_config.Width > MAX_IMAGE_WIDTH || img_config.Height > MAX_IMAGE_HEIGHT {
		img = imaging.Fit(img, MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT, imaging.Lanczos)
	}

	img_buf := new(bytes.Buffer)
	encode_err := jpeg.Encode(img_buf, img, nil)
	if LogErr(encode_err) {
		respond(res, false, nil, "Unable to encode image.")
		return nil
	}

	return img_buf.Bytes()
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

	username := users[fields["access_token"]]
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location)) as latitude, 
      location_name, caption, owner, media_url, media_type, hashtags, created_at, 
      ST_DISTANCE(location, `+point_str+`) as distance,
      COALESCE((SELECT vote FROM Votes v WHERE v.post_id=id and v.username=$1), 0) as my_vote,
      COALESCE((SELECT SUM(vote) FROM Votes v where v.post_id=id), 0) as total_vote
      FROM posts WHERE ST_DWithin(location, `+point_str+`, $2)
      ORDER BY distance ASC`, username, fields["radius"])
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
      ST_DISTANCE(location, `+point_str+`) as distance,
      COALESCE((SELECT vote FROM Votes v WHERE v.post_id=id and v.username=$1), 0) as my_vote,
      COALESCE((SELECT SUM(vote) FROM Votes v where v.post_id=id), 0) as total_vote 
      FROM posts WHERE owner=$1
      ORDER BY created_at DESC`, username)
	if LogErr(db_err) {
		respond(res, false, nil, "Error retrieving rows from database.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, parsePost), nil)
}

func getPostsWithHashtag(res http.ResponseWriter, req *http.Request) {
	fields := extractFields("GET", res, req, "access_token", "latitude", "longitude", "hashtag", "radius")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	username := users[fields["access_token"]]
	hashtag := strings.ToLower(fields["hashtag"])
	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT id, ST_X(ST_AsText(location)) as longitude, ST_Y(ST_AsText(location)) as latitude, 
      location_name, caption, owner, media_url, media_type, hashtags, created_at, 
      ST_DISTANCE(location, `+point_str+`) as distance,
      COALESCE((SELECT vote FROM Votes v WHERE v.post_id=id and v.username=$1), 0) as my_vote,
      COALESCE((SELECT SUM(vote) FROM Votes v where v.post_id=id), 0) as total_vote  
      FROM posts p INNER JOIN (SELECT * FROM Hashtags WHERE hashtag=$2) h 
      ON h.post_id=p.id
      WHERE ST_DWithin(location, `+point_str+`, $3)`, username, hashtag, fields["radius"])
	if LogErr(db_err) {
		respond(res, false, nil, "Error retrieving rows from database.")
		return
	}
	defer rows.Close()

	respond(res, true, rowsToPosts(rows, parsePost), nil)
}

func getHashtagsByPopularity(res http.ResponseWriter, req *http.Request) {
	fields := extractFields("GET", res, req, "access_token", "latitude", "longitude", "radius")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	point_str := pointString(fields["latitude"], fields["longitude"])
	rows, db_err := db.Query(
		`SELECT hashtag, COUNT(*) as num_posts 
			FROM (SELECT hashtag, location
							FROM posts p INNER JOIN Hashtags h 
							ON h.post_id=p.id WHERE ST_DWithin(location, `+point_str+`, $1)) j
			GROUP BY hashtag 
			ORDER BY num_posts DESC`, fields["radius"])
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

func upvote(res http.ResponseWriter, req *http.Request) {
	voteHelper(res, req, 1)
}

func downvote(res http.ResponseWriter, req *http.Request) {
	voteHelper(res, req, -1)
}

func voteHelper(res http.ResponseWriter, req *http.Request, vote_value int) {
	fields := extractFields("POST", res, req, "access_token", "post_id")
	if fields == nil {
		return
	}

	if !enforceValidAccessToken(res, fields["access_token"]) {
		return
	}

	username := users[fields["access_token"]]

	// attempt to update vote
	update_result, update_err := db.Exec(
		`UPDATE Votes SET vote=$1 WHERE post_id=$2 AND username=$3`,
		vote_value, fields["post_id"], username)

	// if vote does not exist, insert new vote
	if update_rows, update_rows_err := update_result.RowsAffected(); update_rows == 0 || LogErr(update_rows_err) || LogErr(update_err) {
		insert_result, insert_err := db.Exec(
			`INSERT INTO Votes (post_id, username, vote) SELECT $1, $2, $3
					WHERE NOT EXISTS (SELECT 1 FROM Votes WHERE post_id=$1 AND username=$2)
					AND EXISTS (SELECT 1 From Posts WHERE id=$1)`,
			fields["post_id"], username, vote_value)

		if insert_rows, insert_rows_err := insert_result.RowsAffected(); insert_rows == 0 || LogErr(insert_rows_err) || LogErr(insert_err) {
			respond(res, false, nil, "Error adding vote to database.")
			return
		}
	}

	respond(res, true, nil, nil)
}

func pointString(latitude string, longitude string) string {
	return fmt.Sprintf("ST_GeographyFromText('SRID=4326;POINT(%s %s)')", longitude, latitude)
}

func rowsToPosts(rows *sql.Rows, parse convert) []map[string]string {
	posts := []map[string]string{}
	for rows.Next() {
		posts = append(posts, parse(rows))
	}

	return posts
}

func parsePost(rows *sql.Rows) map[string]string {
	var id, longitude, latitude, location_name, caption, owner, media_url, media_type, hashtags, my_vote, vote_count string
	var created_at time.Time
	var distance float64
	rows.Scan(&id, &longitude, &latitude, &location_name, &caption, &owner,
		&media_url, &media_type, &hashtags, &created_at, &distance, &my_vote, &vote_count)

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
		"my_vote":       my_vote,
		"vote_count":    vote_count,
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

func main() {
	db = setupDB()
	defer db.Close()

	log.Println("Starting server on port", PORT)

	// Development
	http.HandleFunc("/most_recent_image", mostRecentImage)

	// Production
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
	http.HandleFunc("/upvote", upvote)
	http.HandleFunc("/downvote", downvote)
	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}
