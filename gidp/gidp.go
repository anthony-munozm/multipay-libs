package gidp

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anthony-munozm/multipay-libs/logger"
)

// GIDPUser representa un usuario en Google Identity Platform
type GIDPUser struct {
	UID           string         `json:"uid"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Disabled      bool           `json:"disabled"`
	CreationTime  time.Time      `json:"creation_time"`
	ProviderData  []ProviderInfo `json:"provider_data"`
}

// ProviderInfo contiene información del proveedor de autenticación
type ProviderInfo struct {
	ProviderID string `json:"provider_id"`
	UID        string `json:"uid"`
	Email      string `json:"email"`
}

// Códigos de error estándar de GIDP
const (
	GIDPErrorUnknown            = "UNKNOWN"
	GIDPErrorEmailAlreadyExists = "EMAIL_ALREADY_EXISTS"
	GIDPErrorUserNotFound       = "USER_NOT_FOUND"
	GIDPErrorInvalidCredentials = "INVALID_CREDENTIALS"
	GIDPErrorConfig             = "CONFIG_ERROR"
	GIDPErrorNetwork            = "NETWORK_ERROR"
	GIDPErrorTimeout            = "TIMEOUT"
	GIDPErrorInvalidToken       = "INVALID_TOKEN"
	GIDPErrorTokenExpired       = "TOKEN_EXPIRED"
)

// GIDPError representa un error de la API de GIDP
type GIDPError struct {
	Code        string
	Message     string
	IsRetryable bool
	Raw         interface{} // Respuesta cruda opcional (para logs)
}

func (e *GIDPError) Error() string {
	return fmt.Sprintf("GIDP Error [%s]: %s", e.Code, e.Message)
}

// GIDPClient maneja la comunicación con Google Identity Platform
type GIDPClient struct {
	projectID                string
	apiKey                   string
	serviceURL               string
	tenantID                 string
	httpClient               *http.Client
	enabled                  bool
	passwordResetURLTemplate string // Template opcional para construir links de reset password (ej: "https://myapp.com/reset-password?oobCode=%s")
}

var GIDPC *GIDPClient

// NewGIDPClient crea una nueva instancia del cliente GIDP
// projectID: ID del proyecto de Google Identity Platform (requerido si enabled=true)
// apiKey: API Key de Google Identity Platform (requerido si enabled=true)
// serviceURL: URL del servicio (opcional, por defecto: "https://identitytoolkit.googleapis.com/v1")
// tenantID: ID del tenant para multi-tenancy (opcional)
// timeoutSeconds: Timeout en segundos (opcional, por defecto: 60)
// enabled: Si el cliente está habilitado (opcional, por defecto: false)
// passwordResetURLTemplate: Template opcional para construir links de reset password. Debe contener %s donde se insertará el oobCode.
//
//	Ejemplo: "https://myapp.com/reset-password?oobCode=%s" o "https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=API_KEY&oobCode=%s"
//	Si está vacío, no se construirá el link y solo se retornará el oobCode.
func NewGIDPClient(projectID, apiKey, serviceURL, tenantID string, timeoutSeconds int, enabled bool, passwordResetURLTemplate string) *GIDPClient {
	// Valores por defecto
	if serviceURL == "" {
		serviceURL = "https://identitytoolkit.googleapis.com/v1"
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}

	// Configurar Transport HTTP más robusto para evitar timeouts
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		DisableKeepAlives:     false,
	}

	client := &GIDPClient{
		projectID:  projectID,
		apiKey:     apiKey,
		serviceURL: serviceURL,
		tenantID:   tenantID,
		httpClient: &http.Client{
			Timeout:   time.Duration(timeoutSeconds) * time.Second,
			Transport: transport,
		},
		enabled:                  enabled,
		passwordResetURLTemplate: passwordResetURLTemplate,
	}

	// Si no está habilitado, retornar cliente en modo deshabilitado
	if !enabled {
		if logger.Logger != nil {
			logger.Logger.Info("GIDP Client disabled")
		}
		GIDPC = client
		return client
	}

	// Validar que los parámetros requeridos estén presentes
	if projectID == "" || apiKey == "" {
		if logger.Logger != nil {
			logger.Logger.Info("GIDP Client: Missing configuration (project_id or api_key)")
		}
		client.enabled = false
	}

	GIDPC = client
	return client
}

// NewGIDPClientFromEnv crea una nueva instancia del cliente GIDP leyendo la configuración desde variables de entorno
// Esta función es un helper para facilitar la migración, pero se recomienda usar NewGIDPClient con parámetros explícitos
func NewGIDPClientFromEnv() *GIDPClient {
	enabled := os.Getenv("GIDP_ENABLED")
	isEnabled := enabled == "true" || enabled == "1"

	serviceURL := os.Getenv("GIDP_SERVICE_URL")
	tenantID := os.Getenv("GIDP_TENANT_ID")
	projectID := os.Getenv("GIDP_PROJECT_ID")
	apiKey := os.Getenv("GIDP_API_KEY")
	passwordResetURLTemplate := os.Getenv("GIDP_PASSWORD_RESET_URL_TEMPLATE")

	timeoutSeconds := 60
	if timeoutStr := os.Getenv("GIDP_TIMEOUT_SECONDS"); timeoutStr != "" {
		if parsed, err := strconv.Atoi(timeoutStr); err == nil && parsed > 0 {
			timeoutSeconds = parsed
		}
	}

	return NewGIDPClient(projectID, apiKey, serviceURL, tenantID, timeoutSeconds, isEnabled, passwordResetURLTemplate)
}

// CreateUserWithEmailPassword crea un usuario en GIDP con email y contraseña
func (c *GIDPClient) CreateUserWithEmailPassword(email, password string) (*GIDPUser, error) {
	// Si no hay password, generar uno temporal
	// Nota: En producción, esto debería manejarse con un flujo de invitación
	if password == "" {
		// Generar password temporal (el usuario deberá cambiarlo en el primer login)
		password = generateTemporaryPassword()
	}

	requestBody := map[string]interface{}{
		"email":             email,
		"password":          password,
		"returnSecureToken": false, // No necesitamos el token en el servidor
	}

	responseBody, err := c.makeRequest("POST", "accounts:signUp", requestBody)
	if err != nil {
		return nil, err
	}

	var signUpResp struct {
		LocalID       string `json:"localId"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
	}

	if err := json.Unmarshal(responseBody, &signUpResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	// Crear usuario GIDP usando la información de signUp
	gidpUser := &GIDPUser{
		UID:           signUpResp.LocalID,
		Email:         signUpResp.Email,
		EmailVerified: signUpResp.EmailVerified,
		Disabled:      false,
		CreationTime:  time.Now(),
		ProviderData: []ProviderInfo{
			{
				ProviderID: "password",
				UID:        signUpResp.LocalID,
				Email:      signUpResp.Email,
			},
		},
	}

	return gidpUser, nil
}

// generateTemporaryPassword genera una contraseña temporal segura
func generateTemporaryPassword() string {
	// Generar password temporal de 16 caracteres usando crypto/rand para mayor seguridad
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, 16)
	charsLen := big.NewInt(int64(len(chars)))

	for i := range password {
		n, err := rand.Int(rand.Reader, charsLen)
		if err != nil {
			// Fallback a timestamp si hay error (no debería pasar)
			password[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		} else {
			password[i] = chars[n.Int64()]
		}
	}
	return string(password)
}

// IsEnabled retorna si el cliente GIDP está habilitado
func (c *GIDPClient) IsEnabled() bool {
	return c.enabled
}

// GetTenantID retorna el tenant ID configurado
func (c *GIDPClient) GetTenantID() string {
	return c.tenantID
}

// GetProjectID retorna el project ID configurado
func (c *GIDPClient) GetProjectID() string {
	return c.projectID
}

// GetServiceURL retorna la URL del servicio configurada
func (c *GIDPClient) GetServiceURL() string {
	return c.serviceURL
}

// PasswordResetLinkResponse representa la respuesta de GeneratePasswordResetLink
type PasswordResetLinkResponse struct {
	Email   string `json:"email"`
	Link    string `json:"link,omitempty"`     // Solo para desarrollo/debug
	OobCode string `json:"oob_code,omitempty"` // Código OOB si está disponible
}

// SignInResponse representa la respuesta de SignInWithPassword
type SignInResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UID          string `json:"uid"` // localId de GIDP
	Email        string `json:"email"`
	ExpiresIn    string `json:"expires_in,omitempty"`
}

// TokenValidationResponse representa la respuesta de ValidateIDToken
type TokenValidationResponse struct {
	UID           string `json:"uid"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Disabled      bool   `json:"disabled"`
}

// makeRequest realiza una petición HTTP a la API de GIDP con retry automático
func (c *GIDPClient) makeRequest(method, endpoint string, body map[string]interface{}) ([]byte, error) {
	if !c.enabled {
		return nil, &GIDPError{
			Code:        GIDPErrorConfig,
			Message:     "GIDP client is disabled",
			IsRetryable: false,
		}
	}

	url := fmt.Sprintf("%s/%s?key=%s", c.serviceURL, endpoint, c.apiKey)

	// Agregar tenant_id al body si está configurado
	if c.tenantID != "" && body != nil {
		body["tenant_id"] = c.tenantID
	}

	var jsonData []byte
	var err error
	if body != nil {
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, &GIDPError{
				Code:        GIDPErrorConfig,
				Message:     fmt.Sprintf("error marshaling request: %v", err),
				IsRetryable: false,
			}
		}
	}

	// Intentar hasta 3 veces con retry
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		var req *http.Request
		if jsonData != nil {
			req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
		} else {
			req, err = http.NewRequest(method, url, nil)
		}
		if err != nil {
			return nil, &GIDPError{
				Code:        GIDPErrorConfig,
				Message:     fmt.Sprintf("error creating request: %v", err),
				IsRetryable: false,
			}
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "multipay-libs/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			// Si es un error de red y no es el último intento, esperar y reintentar
			if attempt < maxRetries {
				waitTime := time.Duration(attempt) * time.Second
				if logger.Logger != nil {
					logger.Logger.Info(fmt.Sprintf("GIDP API call failed (attempt %d/%d), retrying in %v: %v", attempt, maxRetries, waitTime, err))
				}
				time.Sleep(waitTime)
				continue
			}
			// Determinar si es timeout o error de red
			isTimeout := strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "TLS handshake timeout")
			errorCode := GIDPErrorNetwork
			if isTimeout {
				errorCode = GIDPErrorTimeout
			}
			return nil, &GIDPError{
				Code:        errorCode,
				Message:     fmt.Sprintf("error calling GIDP API after %d attempts: %v", maxRetries, err),
				IsRetryable: true,
			}
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, &GIDPError{
				Code:        GIDPErrorNetwork,
				Message:     fmt.Sprintf("error reading response: %v", err),
				IsRetryable: false,
			}
		}

		if resp.StatusCode != http.StatusOK {
			var errorResp map[string]interface{}
			if err := json.Unmarshal(responseBody, &errorResp); err == nil {
				if errorData, ok := errorResp["error"].(map[string]interface{}); ok {
					message := "unknown error"
					if msg, ok := errorData["message"].(string); ok {
						message = msg
					}

					// Mapear errores comunes a códigos estándar
					errorCode := c.mapErrorCode(resp.StatusCode, errorData, message)
					isRetryable := errorCode == GIDPErrorNetwork || errorCode == GIDPErrorTimeout

					return nil, &GIDPError{
						Code:        errorCode,
						Message:     message,
						IsRetryable: isRetryable,
						Raw:         errorResp,
					}
				}
			}
			return nil, &GIDPError{
				Code:        GIDPErrorUnknown,
				Message:     fmt.Sprintf("GIDP API error: status %d, body: %s", resp.StatusCode, string(responseBody)),
				IsRetryable: false,
			}
		}

		// Si llegamos aquí, la request fue exitosa
		return responseBody, nil
	}

	// Si llegamos aquí, todos los intentos fallaron
	return nil, &GIDPError{
		Code:        GIDPErrorNetwork,
		Message:     fmt.Sprintf("GIDP API call failed after %d attempts: %v", maxRetries, lastErr),
		IsRetryable: true,
	}
}

// mapErrorCode mapea errores de GIDP a códigos estándar
func (c *GIDPClient) mapErrorCode(statusCode int, errorData map[string]interface{}, message string) string {
	// Verificar códigos específicos de GIDP
	if code, ok := errorData["code"].(float64); ok {
		switch int(code) {
		case 400:
			// Verificar si es email duplicado
			if strings.Contains(strings.ToLower(message), "email") && strings.Contains(strings.ToLower(message), "exists") {
				return GIDPErrorEmailAlreadyExists
			}
			return GIDPErrorInvalidCredentials
		case 401:
			return GIDPErrorInvalidCredentials
		case 404:
			return GIDPErrorUserNotFound
		}
	}

	// Mapear por status code HTTP
	switch statusCode {
	case http.StatusBadRequest:
		if strings.Contains(strings.ToLower(message), "email") && strings.Contains(strings.ToLower(message), "exists") {
			return GIDPErrorEmailAlreadyExists
		}
		return GIDPErrorInvalidCredentials
	case http.StatusUnauthorized:
		return GIDPErrorInvalidCredentials
	case http.StatusNotFound:
		return GIDPErrorUserNotFound
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return GIDPErrorTimeout
	case http.StatusServiceUnavailable, http.StatusBadGateway:
		return GIDPErrorNetwork
	default:
		return GIDPErrorUnknown
	}
}

// SignInWithPassword autentica un usuario con GIDP usando email/password
func (c *GIDPClient) SignInWithPassword(email, password string) (*SignInResponse, error) {
	body := map[string]interface{}{
		"email":             email,
		"password":          password,
		"returnSecureToken": true,
	}

	responseBody, err := c.makeRequest("POST", "accounts:signInWithPassword", body)
	if err != nil {
		return nil, err
	}

	var signInResp struct {
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken,omitempty"`
		LocalID      string `json:"localId"`
		Email        string `json:"email"`
		ExpiresIn    string `json:"expiresIn,omitempty"`
	}

	if err := json.Unmarshal(responseBody, &signInResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	if signInResp.IDToken == "" {
		return nil, &GIDPError{
			Code:        GIDPErrorInvalidToken,
			Message:     "idToken not found in response",
			IsRetryable: false,
		}
	}

	if signInResp.LocalID == "" {
		return nil, &GIDPError{
			Code:        GIDPErrorUserNotFound,
			Message:     "localId not found in response",
			IsRetryable: false,
		}
	}

	return &SignInResponse{
		IDToken:      signInResp.IDToken,
		RefreshToken: signInResp.RefreshToken,
		UID:          signInResp.LocalID,
		Email:        signInResp.Email,
		ExpiresIn:    signInResp.ExpiresIn,
	}, nil
}

// GeneratePasswordResetLink genera un link de reset/set password y lo envía por email
func (c *GIDPClient) GeneratePasswordResetLink(email string) (*PasswordResetLinkResponse, error) {
	body := map[string]interface{}{
		"requestType": "PASSWORD_RESET",
		"email":       email,
	}

	responseBody, err := c.makeRequest("POST", "accounts:sendOobCode", body)
	if err != nil {
		return nil, err
	}

	var oobResp struct {
		Email   string `json:"email"`
		OobCode string `json:"oobCode,omitempty"`
	}

	if err := json.Unmarshal(responseBody, &oobResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	response := &PasswordResetLinkResponse{
		Email:   oobResp.Email,
		OobCode: oobResp.OobCode,
	}

	// Construir link solo si hay oobCode y está configurado el template
	if oobResp.OobCode != "" && c.passwordResetURLTemplate != "" {
		// Si el template contiene %s, reemplazarlo con el oobCode
		// Si contiene API_KEY, reemplazarlo con la API key (para compatibilidad con URLs de GIDP)
		template := strings.ReplaceAll(c.passwordResetURLTemplate, "API_KEY", c.apiKey)
		response.Link = fmt.Sprintf(template, oobResp.OobCode)
	}

	return response, nil
}

// ValidateIDToken valida y decodifica un ID Token de GIDP usando la API de Google
func (c *GIDPClient) ValidateIDToken(idToken string) (*TokenValidationResponse, error) {
	// Validar formato básico del token
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, &GIDPError{
			Code:        GIDPErrorInvalidToken,
			Message:     "invalid token format",
			IsRetryable: false,
		}
	}

	body := map[string]interface{}{
		"idToken": idToken,
	}

	responseBody, err := c.makeRequest("POST", "accounts:lookup", body)
	if err != nil {
		return nil, err
	}

	var lookupResp struct {
		Users []struct {
			LocalID       string `json:"localId"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
			Disabled      bool   `json:"disabled"`
		} `json:"users"`
	}

	if err := json.Unmarshal(responseBody, &lookupResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	if len(lookupResp.Users) == 0 {
		return nil, &GIDPError{
			Code:        GIDPErrorUserNotFound,
			Message:     "no user found in validation response",
			IsRetryable: false,
		}
	}

	user := lookupResp.Users[0]
	if user.LocalID == "" {
		return nil, &GIDPError{
			Code:        GIDPErrorUserNotFound,
			Message:     "localId not found in validation response",
			IsRetryable: false,
		}
	}

	return &TokenValidationResponse{
		UID:           user.LocalID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Disabled:      user.Disabled,
	}, nil
}

// GetUserByUID obtiene información de un usuario en GIDP por su UID
func (c *GIDPClient) GetUserByUID(uid string) (*GIDPUser, error) {
	body := map[string]interface{}{
		"localId": []string{uid},
	}

	responseBody, err := c.makeRequest("POST", "accounts:lookup", body)
	if err != nil {
		return nil, err
	}

	var lookupResp struct {
		Users []struct {
			LocalID          string `json:"localId"`
			Email            string `json:"email"`
			EmailVerified    bool   `json:"emailVerified"`
			Disabled         bool   `json:"disabled"`
			CreatedAt        int64  `json:"createdAt,string"`
			ProviderUserInfo []struct {
				ProviderID  string `json:"providerId"`
				FederatedID string `json:"federatedId"`
				Email       string `json:"email"`
			} `json:"providerUserInfo"`
		} `json:"users"`
	}

	if err := json.Unmarshal(responseBody, &lookupResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	if len(lookupResp.Users) == 0 {
		return nil, &GIDPError{
			Code:        GIDPErrorUserNotFound,
			Message:     fmt.Sprintf("user with UID %s not found", uid),
			IsRetryable: false,
		}
	}

	userData := lookupResp.Users[0]

	// Convertir providerUserInfo a ProviderInfo
	providers := make([]ProviderInfo, len(userData.ProviderUserInfo))
	for i, p := range userData.ProviderUserInfo {
		providers[i] = ProviderInfo{
			ProviderID: p.ProviderID,
			UID:        p.FederatedID,
			Email:      p.Email,
		}
	}

	// Convertir createdAt (timestamp en milisegundos) a time.Time
	creationTime := time.Now()
	if userData.CreatedAt > 0 {
		creationTime = time.Unix(userData.CreatedAt/1000, 0)
	}

	return &GIDPUser{
		UID:           userData.LocalID,
		Email:         userData.Email,
		EmailVerified: userData.EmailVerified,
		Disabled:      userData.Disabled,
		CreationTime:  creationTime,
		ProviderData:  providers,
	}, nil
}

// GetUserByEmail obtiene información de un usuario en GIDP por su email
func (c *GIDPClient) GetUserByEmail(email string) (*GIDPUser, error) {
	body := map[string]interface{}{
		"email": []string{email},
	}

	responseBody, err := c.makeRequest("POST", "accounts:lookup", body)
	if err != nil {
		return nil, err
	}

	var lookupResp struct {
		Users []struct {
			LocalID          string `json:"localId"`
			Email            string `json:"email"`
			EmailVerified    bool   `json:"emailVerified"`
			Disabled         bool   `json:"disabled"`
			CreatedAt        int64  `json:"createdAt,string"`
			ProviderUserInfo []struct {
				ProviderID  string `json:"providerId"`
				FederatedID string `json:"federatedId"`
				Email       string `json:"email"`
			} `json:"providerUserInfo"`
		} `json:"users"`
	}

	if err := json.Unmarshal(responseBody, &lookupResp); err != nil {
		return nil, &GIDPError{
			Code:        GIDPErrorUnknown,
			Message:     fmt.Sprintf("error unmarshaling response: %v", err),
			IsRetryable: false,
		}
	}

	if len(lookupResp.Users) == 0 {
		return nil, &GIDPError{
			Code:        GIDPErrorUserNotFound,
			Message:     fmt.Sprintf("user with email %s not found", email),
			IsRetryable: false,
		}
	}

	userData := lookupResp.Users[0]

	// Convertir providerUserInfo a ProviderInfo
	providers := make([]ProviderInfo, len(userData.ProviderUserInfo))
	for i, p := range userData.ProviderUserInfo {
		providers[i] = ProviderInfo{
			ProviderID: p.ProviderID,
			UID:        p.FederatedID,
			Email:      p.Email,
		}
	}

	// Convertir createdAt (timestamp en milisegundos) a time.Time
	creationTime := time.Now()
	if userData.CreatedAt > 0 {
		creationTime = time.Unix(userData.CreatedAt/1000, 0)
	}

	return &GIDPUser{
		UID:           userData.LocalID,
		Email:         userData.Email,
		EmailVerified: userData.EmailVerified,
		Disabled:      userData.Disabled,
		CreationTime:  creationTime,
		ProviderData:  providers,
	}, nil
}

// SendEmailVerification envía un correo de verificación de email al usuario
// Requiere el idToken del usuario o su email
func (c *GIDPClient) SendEmailVerification(idTokenOrEmail string) error {
	body := map[string]interface{}{
		"requestType": "VERIFY_EMAIL",
	}

	// Si parece un email (contiene @), usar email, sino asumir que es idToken
	if strings.Contains(idTokenOrEmail, "@") {
		body["email"] = idTokenOrEmail
	} else {
		body["idToken"] = idTokenOrEmail
	}

	_, err := c.makeRequest("POST", "accounts:sendOobCode", body)
	if err != nil {
		return err
	}

	return nil
}
