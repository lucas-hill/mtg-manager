package httpx

import "net/http"

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	res, err := s.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	// 200 (not 201): login creates no new resource.
	writeJSON(w, http.StatusOK, authResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		User:         userDTO{ID: res.User.ID, Email: res.User.Email, Name: res.User.Name},
	})
}
