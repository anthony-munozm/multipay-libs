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

// GIDPError representa un error de la API de GIDP
type GIDPError struct {
	Code    string
	Message string
}

func (e *GIDPError) Error() string {
	return fmt.Sprintf("GIDP Error [%s]: %s", e.Code, e.Message)
}

// GIDPClient maneja la comunicación con Google Identity Platform
type GIDPClient struct {
	projectID  string
	apiKey     string
	serviceURL string
	tenantID   string
	httpClient *http.Client
	enabled    bool
}

var GIDPC *GIDPClient

// NewGIDPClient crea una nueva instancia del cliente GIDP
// projectID: ID del proyecto de Google Identity Platform (requerido si enabled=true)
// apiKey: API Key de Google Identity Platform (requerido si enabled=true)
// serviceURL: URL del servicio (opcional, por defecto: "https://identitytoolkit.googleapis.com/v1")
// tenantID: ID del tenant para multi-tenancy (opcional)
// timeoutSeconds: Timeout en segundos (opcional, por defecto: 60)
// enabled: Si el cliente está habilitado (opcional, por defecto: false)
func NewGIDPClient(projectID, apiKey, serviceURL, tenantID string, timeoutSeconds int, enabled bool) *GIDPClient {
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
		enabled: enabled,
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

	timeoutSeconds := 60
	if timeoutStr := os.Getenv("GIDP_TIMEOUT_SECONDS"); timeoutStr != "" {
		if parsed, err := strconv.Atoi(timeoutStr); err == nil && parsed > 0 {
			timeoutSeconds = parsed
		}
	}

	return NewGIDPClient(projectID, apiKey, serviceURL, tenantID, timeoutSeconds, isEnabled)
}

// CreateUserWithEmailPassword crea un usuario en GIDP con email y contraseña
func (c *GIDPClient) CreateUserWithEmailPassword(email, password string) (*GIDPUser, error) {
	if !c.enabled {
		return nil, fmt.Errorf("GIDP client is disabled")
	}

	// Si no hay password, generar uno temporal
	// Nota: En producción, esto debería manejarse con un flujo de invitación
	if password == "" {
		// Generar password temporal (el usuario deberá cambiarlo en el primer login)
		password = generateTemporaryPassword()
	}

	url := fmt.Sprintf("%s/accounts:signUp?key=%s", c.serviceURL, c.apiKey)

	requestBody := map[string]interface{}{
		"email":             email,
		"password":          password,
		"returnSecureToken": false, // No necesitamos el token en el servidor
	}

	// Agregar tenant_id solo si está configurado
	if c.tenantID != "" {
		requestBody["tenant_id"] = c.tenantID
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}

	// Intentar hasta 3 veces con retry
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
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
			return nil, fmt.Errorf("error calling GIDP API after %d attempts: %w", maxRetries, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			var errorResp map[string]interface{}
			if err := json.Unmarshal(body, &errorResp); err == nil {
				if errorData, ok := errorResp["error"].(map[string]interface{}); ok {
					message := "unknown error"
					if msg, ok := errorData["message"].(string); ok {
						message = msg
					}

					// Detectar errores comunes
					errorCode := fmt.Sprintf("GIDP_%d", resp.StatusCode)
					if resp.StatusCode == http.StatusBadRequest {
						// Email ya existe u otro error de validación
						if code, ok := errorData["code"].(float64); ok {
							if code == 400 {
								errorCode = "GIDP_EMAIL_EXISTS"
								if message == "unknown error" {
									message = "Email already exists in Google Identity Platform"
								}
							}
						}
					}

					return nil, &GIDPError{
						Code:    errorCode,
						Message: message,
					}
				}
			}
			return nil, fmt.Errorf("GIDP API error: status %d, body: %s", resp.StatusCode, string(body))
		}

		// Si llegamos aquí, la request fue exitosa
		var signUpResp struct {
			LocalID       string `json:"localId"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		}

		if err := json.Unmarshal(body, &signUpResp); err != nil {
			return nil, fmt.Errorf("error unmarshaling response: %w", err)
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

	// Si llegamos aquí, todos los intentos fallaron
	return nil, fmt.Errorf("GIDP API call failed after %d attempts: %w", maxRetries, lastErr)
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
