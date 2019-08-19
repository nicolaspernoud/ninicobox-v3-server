package onlyoffice

import (
	"encoding/json"
	"net/http"
)

// HandleSaveCallback is the callback function wanted by onlyoffice to allow saving a document
// the body provides information on where to get the altered document, and the query provides information on where to put it
func HandleSaveCallback(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "the request method must be POST", 405)
		return
	}
	if req.Body == nil {
		http.Error(w, "the request must contain a body", 400)
		return
	}
	var bdy struct {
		Actions []struct {
			Type   int    `json:"type"`
			Userid string `json:"userid"`
		} `json:"actions"`
		Changesurl string `json:"changesurl"`
		History    struct {
			Changes       string `json:"changes"`
			ServerVersion string `json:"serverVersion"`
		} `json:"history"`
		Key    string   `json:"key"`
		Status int      `json:"status"`
		URL    string   `json:"url"`
		Users  []string `json:"users"`
	}
	jsonErr := json.NewDecoder(req.Body).Decode(&bdy)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), 400)
		return
	}
	// Case of document closed after editing
	if bdy.Status == 2 {
		// Get the binary content from url
		resp, err := http.Get(bdy.URL)
		if err != nil {
			http.Error(w, "could not get connect to onlyoffice document server", 400)
			return
		}
		defer resp.Body.Close()
		// PUT the content on the ressource gotten from the query
		ressource := req.URL.Query().Get("file") + "?token=" + req.URL.Query().Get("token")
		req, err := http.NewRequest("PUT", ressource, resp.Body)
		client := &http.Client{}
		_, err = client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write([]byte("{\"error\":0}"))
	}
}
