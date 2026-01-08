package iam

import (
	"os"
	"strconv"
	"context"
	"fmt"
	"net/http"
	"strings"
	"slices"
	"time"
	"github.com/anthony-munozm/multipay-libs/errormap"
	"github.com/anthony-munozm/multipay-libs/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// IAMClaims representa los claims IAM que se incluyen en el JWT
type IAMClaims struct {
	Sub         string   `json:"sub"`          // admin_user.id (UUID interno Multipay)
	SubjectKind string   `json:"subject_kind"` // "human"
	IDP         string   `json:"idp"`          // "gidp"
	IDPSub      string   `json:"idp_sub"`      // UID del usuario en GIDP
	UserType    string   `json:"user_type"`    // platform_admin, tenant_admin, support, auditor
	TenantID    *string  `json:"tenant_id"`    // UUID del tenant o null
	CountryCode string   `json:"country_code"` // ISO 3166 (ej: "CR")
	Channel     string   `json:"channel"`      // "web" (MVP)
	Roles       []string `json:"roles"`        // ROLE_PLATFORM_ADMIN, etc.
	Scopes      []string `json:"scopes"`       // admin:users:read, etc.
	Locale      string   `json:"locale"`       // "es-CR"
	IdempotencyKey string `json:"idempotency_key"` // Key for idempotency
}

// IAMContext representa el contexto IAM extraído del JWT y disponible en la request
type IAMContext struct {
	SubjectKind string   // "human"
	UserType    string   // "platform_admin", "tenant_admin", "support", "auditor"
	TenantID    string   // UUID del tenant o "" si es platform
	CountryCode string   // "CR"
	Channel     string   // "web"
	Roles       []string // ["ROLE_PLATFORM_ADMIN", ...]
	Scopes      []string // ["admin:users:read", ...]
	Locale      string   // "es-CR"
	UserID      string   // ID interno del usuario (sub del JWT)
}

// HasScope verifica si el contexto tiene un scope específico
func (ctx *IAMContext) HasScope(scope string) bool {
	for _, s := range ctx.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope verifica si el contexto tiene al menos uno de los scopes proporcionados
func (ctx *IAMContext) HasAnyScope(scopes ...string) bool {
	for _, requiredScope := range scopes {
		if ctx.HasScope(requiredScope) {
			return true
		}
	}
	return false
}

// HasRole verifica si el contexto tiene un role específico
func (ctx *IAMContext) HasRole(role string) bool {
	for _, r := range ctx.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole verifica si el contexto tiene al menos uno de los roles proporcionados
func (ctx *IAMContext) HasAnyRole(roles ...string) bool {
	for _, requiredRole := range roles {
		if ctx.HasRole(requiredRole) {
			return true
		}
	}
	return false
}

// IsUserType verifica si el contexto tiene un user_type específico
func (ctx *IAMContext) IsUserType(userType string) bool {
	return ctx.UserType == userType
}

// IsAnyUserType verifica si el contexto tiene alguno de los user_types proporcionados
func (ctx *IAMContext) IsAnyUserType(userTypes ...string) bool {
	for _, ut := range userTypes {
		if ctx.IsUserType(ut) {
			return true
		}
	}
	return false
}


// IAM JWT configuration functions
func GetIAMJWTSigningKey() string {
	return os.Getenv("IAM_JWT_SIGNING_KEY")
}

func GetIAMJWTIssuer() string {
	issuer := os.Getenv("IAM_JWT_ISSUER")
	if issuer == "" {
		return "https://iam.multipay.internal"
	}
	return issuer
}

func GetIAMJWTAudience() string {
	audience := os.Getenv("IAM_JWT_AUDIENCE")
	if audience == "" {
		return "multipay-admin-apis"
	}
	return audience
}

func GetIAMJWTTTLMinutes() int {
	if ttlStr := os.Getenv("IAM_JWT_TTL_MINUTES"); ttlStr != "" {
		if parsed, err := strconv.Atoi(ttlStr); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 3600 // default 60 minutes (3600 seconds / 60 = 60 minutes, but we store in minutes)
}

func GetJWTRequired() bool {
	required := os.Getenv("JWT_REQUIRED")
	if required == "" {
		return true
	}
	return required == "true" || required == "1"
}

// Context key para IAMContext
type iamContextKey struct{}

// IAMContextKey es la clave para obtener IAMContext del contexto
var IAMContextKey = &iamContextKey{}

// extractIAMClaimsFromRequest extrae y valida los claims IAM del JWT en el Authorization header
func extractIAMClaimsFromRequest(c echo.Context) (*IAMClaims, error) {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header missing")
	}

	// Extraer el token (Bearer <token>)
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	tokenString := parts[1]

	// Obtener signing key
	signingKey := GetIAMJWTSigningKey()
	if signingKey == "" {
		return nil, fmt.Errorf("IAM_JWT_SIGNING_KEY not configured")
	}

	// Parsear y validar el token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(signingKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extraer claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validar issuer (iss)
	expectedIssuer := GetIAMJWTIssuer()
	if issuer, ok := claims["iss"].(string); ok {
		if issuer != expectedIssuer {
			return nil, fmt.Errorf("IAM_INVALID_ISSUER: expected %s, got %s", expectedIssuer, issuer)
		}
	} else {
		return nil, fmt.Errorf("IAM_INVALID_ISSUER: missing issuer (iss) claim")
	}

	// Validar audience (aud)
	expectedAudience := GetIAMJWTAudience()
	if audience, ok := claims["aud"].(string); ok {
		if audience != expectedAudience {
			return nil, fmt.Errorf("IAM_INVALID_AUDIENCE: expected %s, got %s", expectedAudience, audience)
		}
	} else {
		return nil, fmt.Errorf("IAM_INVALID_AUDIENCE: missing audience (aud) claim")
	}

	// Construir IAMClaims
	iamClaims := &IAMClaims{}

	if sub, ok := claims["sub"].(string); ok {
		iamClaims.Sub = sub
	}

	if subjectKind, ok := claims["subject_kind"].(string); ok {
		iamClaims.SubjectKind = subjectKind
	}

	if userType, ok := claims["user_type"].(string); ok {
		iamClaims.UserType = userType
	}

	if countryCode, ok := claims["country_code"].(string); ok {
		iamClaims.CountryCode = countryCode
	}

	if channel, ok := claims["channel"].(string); ok {
		iamClaims.Channel = channel
	}

	if locale, ok := claims["locale"].(string); ok {
		iamClaims.Locale = locale
	}

	if roles, ok := claims["roles"].([]interface{}); ok {
		iamClaims.Roles = make([]string, len(roles))
		for i, r := range roles {
			if role, ok := r.(string); ok {
				iamClaims.Roles[i] = role
			}
		}
	}

	if scopes, ok := claims["scopes"].([]interface{}); ok {
		iamClaims.Scopes = make([]string, len(scopes))
		for i, s := range scopes {
			if scope, ok := s.(string); ok {
				iamClaims.Scopes[i] = scope
			}
		}
	}

	// tenant_id puede ser string o null
	if tenantID, ok := claims["tenant_id"].(string); ok && tenantID != "" {
		iamClaims.TenantID = &tenantID
	}

	if idempotencyKey, ok := claims["idempotency_key"].(string); ok {
		iamClaims.IdempotencyKey = idempotencyKey
	}

	return iamClaims, nil
}

// buildIAMContext construye IAMContext desde IAMClaims
func buildIAMContext(claims *IAMClaims) *IAMContext {
	ctx := &IAMContext{
		SubjectKind: claims.SubjectKind,
		UserType:    claims.UserType,
		CountryCode: claims.CountryCode,
		Channel:     claims.Channel,
		Roles:       claims.Roles,
		Scopes:      claims.Scopes,
		Locale:      claims.Locale,
		UserID:      claims.Sub,
	}

	if claims.TenantID != nil {
		ctx.TenantID = *claims.TenantID
	}

	return ctx
}

// validateIAMContext valida que el IAMContext tenga los campos mínimos requeridos
func validateIAMContext(ctx *IAMContext) error {
	if ctx.SubjectKind != "human" {
		return fmt.Errorf("subject_kind must be 'human'")
	}

	if ctx.CountryCode == "" {
		return fmt.Errorf("country_code is required")
	}

	// tenant_id puede estar vacío para platform_admin
	// roles y scopes pueden estar vacíos, pero es raro para admin-core
	if len(ctx.Roles) == 0 {
		logger.LogInfo("Warning: IAMContext has no roles", nil)
	}

	if len(ctx.Scopes) == 0 {
		logger.LogInfo("Warning: IAMContext has no scopes", nil)
	}

	return nil
}

// reissueJWTWithIdempotencyKey re-issues a JWT with an updated idempotency key
func reissueJWTWithIdempotencyKey(originalClaims *IAMClaims, idempotencyKey string) (string, error) {
	// Obtener configuración
	issuer := GetIAMJWTIssuer()
	audience := GetIAMJWTAudience()
	ttlMinutes := GetIAMJWTTTLMinutes()
	signingKey := GetIAMJWTSigningKey()
	if signingKey == "" {
		return "", fmt.Errorf("IAM_JWT_SIGNING_KEY not configured")
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttlMinutes) * time.Minute)

	// Crear claims JWT con el idempotency key actualizado
	jwtClaims := jwt.MapClaims{
		"sub":             originalClaims.Sub,
		"subject_kind":    originalClaims.SubjectKind,
		"idp":             originalClaims.IDP,
		"idp_sub":         originalClaims.IDPSub,
		"user_type":       originalClaims.UserType,
		"country_code":    originalClaims.CountryCode,
		"channel":         originalClaims.Channel,
		"roles":           originalClaims.Roles,
		"scopes":          originalClaims.Scopes,
		"locale":          originalClaims.Locale,
		"iss":             issuer,
		"aud":             audience,
		"iat":             now.Unix(),
		"exp":             expiresAt.Unix(),
		"idempotency_key": idempotencyKey,
	}

	if originalClaims.TenantID != nil {
		jwtClaims["tenant_id"] = *originalClaims.TenantID
	}

	// Crear y firmar el nuevo token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// IAMAuthMiddleware es el middleware de autorización IAM
func IAMAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		currentIdempotencyKey := c.Request().Header.Get("Idempotency-Key")

		// Extraer y validar claims del JWT
		claims, err := extractIAMClaimsFromRequest(c)
		if err != nil {
			logger.LogInfo(fmt.Sprintf("IAM auth failed: %v", err), c.Request())

			// Determinar código de error específico basado en el mensaje
			errorCode := "IAM_INVALID_TOKEN"
			errorMsg := err.Error()
			if strings.Contains(errorMsg, "IAM_INVALID_ISSUER") {
				errorCode = "IAM_INVALID_ISSUER"
				errorMsg = strings.TrimPrefix(errorMsg, "IAM_INVALID_ISSUER: ")
			} else if strings.Contains(errorMsg, "IAM_INVALID_AUDIENCE") {
				errorCode = "IAM_INVALID_AUDIENCE"
				errorMsg = strings.TrimPrefix(errorMsg, "IAM_INVALID_AUDIENCE: ")
			}

			return c.JSON(http.StatusUnauthorized, map[string]interface{}{
				"message": errormap.GenerateErrorMessage(errorCode, errorMsg),
				"code":    errorCode,
			})
		}

		var validateJWT = true

		// Construir IAMContext
		iamCtx := buildIAMContext(claims)

		excludeJWTPaths := []string{
			"/api/transaction/healthz",
		}

		if slices.Contains(excludeJWTPaths, c.Request().URL.Path) {
		
			jwtRequired := GetJWTRequired()

			if claims.IdempotencyKey == "" || currentIdempotencyKey != claims.IdempotencyKey {
				newToken, err := reissueJWTWithIdempotencyKey(claims, currentIdempotencyKey)
				if err != nil {
					logger.LogInfo(fmt.Sprintf("Failed to re-issue JWT with idempotency key: %v", err), c.Request())
					return c.JSON(http.StatusInternalServerError, map[string]interface{}{
						"message": errormap.GenerateErrorMessage("IAM_JWT_ISSUE_ERROR", err.Error()),
						"code":    "IAM_JWT_ISSUE_ERROR",
					})
				}
				c.Request().Header.Set("Authorization", "Bearer "+newToken)
				claims.IdempotencyKey = currentIdempotencyKey
				c.Request().Header.Set("Idempotency-Key", currentIdempotencyKey)
			} else if currentIdempotencyKey == claims.IdempotencyKey {
				validateJWT = false
			}

			if validateJWT && jwtRequired {

				// Validar campos mínimos
				if err := validateIAMContext(iamCtx); err != nil {
					logger.LogInfo(fmt.Sprintf("IAM context validation failed: %v", err), c.Request())
					return c.JSON(http.StatusUnauthorized, map[string]interface{}{
						"message": errormap.GenerateErrorMessage("IAM_INVALID_TOKEN", err.Error()),
						"code":    "IAM_INVALID_TOKEN",
					})
				}

			}

		}

		// Agregar IAMContext al contexto de la request
		ctx := context.WithValue(c.Request().Context(), IAMContextKey, iamCtx)
		c.SetRequest(c.Request().WithContext(ctx))

		return next(c)
	}
}

// GetIAMContext obtiene el IAMContext del contexto de la request
func GetIAMContext(c echo.Context) (*IAMContext, error) {
	iamCtx, ok := c.Request().Context().Value(IAMContextKey).(*IAMContext)
	if !ok || iamCtx == nil {
		return nil, fmt.Errorf("IAM context not found in request context")
	}
	return iamCtx, nil
}

// RequireScope verifica que el contexto tenga un scope específico
func RequireScope(scope string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_INVALID_TOKEN_SCOPE", err.Error()),
					"code":    "IAM_INVALID_TOKEN",
				})
			}

			if !iamCtx.HasScope(scope) {
				logAuthorizationDenied(c, "MISSING_REQUIRED_SCOPE", fmt.Sprintf("Required scope: %s", scope))
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_MISSING_SCOPE", fmt.Sprintf("Required scope: %s", scope)),
					"code":    "IAM_MISSING_SCOPE",
				})
			}

			return next(c)
		}
	}
}

// RequireAnyScope verifica que el contexto tenga al menos uno de los scopes proporcionados
func RequireAnyScope(scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_INVALID_TOKEN", err.Error()),
					"code":    "IAM_INVALID_TOKEN",
				})
			}

			if !iamCtx.HasAnyScope(scopes...) {
				logAuthorizationDenied(c, "MISSING_REQUIRED_SCOPE", fmt.Sprintf("Required one of scopes: %v", scopes))
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_MISSING_SCOPE", fmt.Sprintf("Required one of scopes: %v", scopes)),
					"code":    "IAM_MISSING_SCOPE",
				})
			}

			return next(c)
		}
	}
}

// RequireUserType verifica que el contexto tenga un user_type específico
func RequireUserType(userType string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_INVALID_TOKEN", err.Error()),
					"code":    "IAM_INVALID_TOKEN",
				})
			}

			if !iamCtx.IsUserType(userType) {
				logAuthorizationDenied(c, "USER_TYPE_NOT_ALLOWED", fmt.Sprintf("Required user_type: %s", userType))
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_USER_TYPE_NOT_ALLOWED", fmt.Sprintf("Required user_type: %s", userType)),
					"code":    "IAM_USER_TYPE_NOT_ALLOWED",
				})
			}

			return next(c)
		}
	}
}

// RequireAnyUserType verifica que el contexto tenga alguno de los user_types proporcionados
func RequireAnyUserType(userTypes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_INVALID_TOKEN", err.Error()),
					"code":    "IAM_INVALID_TOKEN",
				})
			}

			if !iamCtx.IsAnyUserType(userTypes...) {
				logAuthorizationDenied(c, "USER_TYPE_NOT_ALLOWED", fmt.Sprintf("Required one of user_types: %v", userTypes))
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"message": errormap.GenerateErrorMessage("IAM_USER_TYPE_NOT_ALLOWED", fmt.Sprintf("Required one of user_types: %v", userTypes)),
					"code":    "IAM_USER_TYPE_NOT_ALLOWED",
				})
			}

			return next(c)
		}
	}
}

// logAuthorizationDenied registra un intento de acceso denegado
func logAuthorizationDenied(c echo.Context, reason, details string) {
	iamCtx, err := GetIAMContext(c)
	if err != nil {
		logger.LogInfo(fmt.Sprintf("Authorization denied - %s: %s | Endpoint: %s %s", reason, details, c.Request().Method, c.Request().URL.Path), c.Request())
		return
	}

	logger.LogInfo(fmt.Sprintf("Authorization denied - %s: %s | SubjectKind: %s | UserType: %s | Roles: %v | Scopes: %v | TenantID: %s | CountryCode: %s | Endpoint: %s %s",
		reason, details, iamCtx.SubjectKind, iamCtx.UserType, iamCtx.Roles, iamCtx.Scopes, iamCtx.TenantID, iamCtx.CountryCode, c.Request().Method, c.Request().URL.Path), c.Request())
}