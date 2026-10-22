package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/lsongdev/yabber"
)

func (a *API) listSites(w http.ResponseWriter, _ *http.Request) {
	config := a.server.Config()
	w.Header().Set("ETag", etag(config))
	writeJSON(w, http.StatusOK, nonNil(config.Sites))
}

func (a *API) getSite(w http.ResponseWriter, r *http.Request) {
	config := a.server.Config()
	index := siteIndex(config, r.PathValue("id"))
	if index < 0 {
		writeError(w, http.StatusNotFound, fmt.Errorf("no site %q", r.PathValue("id")))
		return
	}
	w.Header().Set("ETag", etag(config))
	writeJSON(w, http.StatusOK, config.Sites[index])
}

func (a *API) createSite(w http.ResponseWriter, r *http.Request) {
	var site yabber.Site
	if !readJSON(w, r, &site) {
		return
	}
	id := site.ID()
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("a site needs a name or at least one host"))
		return
	}
	if a.change(w, r, func(config *yabber.Config) error {
		if siteIndex(*config, id) >= 0 {
			return &statusError{http.StatusConflict, fmt.Errorf("site %q already exists", id)}
		}
		config.Sites = append(config.Sites, site)
		return nil
	}) {
		w.Header().Set("Location", "/api/sites/"+url.PathEscape(id))
		writeJSON(w, http.StatusCreated, site)
	}
}

// putSite replaces a site. The site keeps the ID in the URL: a body without
// a name gets it, and a body naming another ID is rejected, so renaming is
// an explicit delete and create.
func (a *API) putSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var site yabber.Site
	if !readJSON(w, r, &site) {
		return
	}
	if site.Name == "" && site.ID() != id {
		site.Name = id
	}
	if site.ID() != id {
		writeError(w, http.StatusBadRequest, fmt.Errorf("site name %q does not match %q in the URL", site.ID(), id))
		return
	}
	if a.change(w, r, func(config *yabber.Config) error {
		index := siteIndex(*config, id)
		if index < 0 {
			return &statusError{http.StatusNotFound, fmt.Errorf("no site %q", id)}
		}
		config.Sites[index] = site
		return nil
	}) {
		writeJSON(w, http.StatusOK, site)
	}
}

func (a *API) deleteSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.change(w, r, func(config *yabber.Config) error {
		index := siteIndex(*config, id)
		if index < 0 {
			return &statusError{http.StatusNotFound, fmt.Errorf("no site %q", id)}
		}
		config.Sites = slices.Delete(config.Sites, index, index+1)
		return nil
	}) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func siteIndex(config yabber.Config, id string) int {
	return slices.IndexFunc(config.Sites, func(site yabber.Site) bool { return site.ID() == id })
}
