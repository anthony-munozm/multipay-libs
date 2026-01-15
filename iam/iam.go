package iam

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/anthony-munozm/multipay-libs/errormap"
	"github.com/anthony-munozm/multipay-libs/logger"
	"github.com/anthony-munozm/multipay-libs/redis"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// IAMClaims representa los claims IAM que se incluyen en el JWT
type IAMClaims struct {
	Sub            string   `json:"sub"`             // admin_user.id (UUID interno Multipay)
	SubjectKind    string   `json:"subject_kind"`    // "human"
	IDP            string   `json:"idp"`             // "gidp"
	IDPSub         string   `json:"idp_sub"`         // UID del usuario en GIDP
	UserType       string   `json:"user_type"`       // platform_admin, tenant_admin, support, auditor
	TenantID       *string  `json:"tenant_id"`       // UUID del tenant o null
	CountryCode    string   `json:"country_code"`    // ISO 3166 (ej: "CR")
	Channel        string   `json:"channel"`         // "web" (MVP)
	Roles          []string `json:"roles"`           // ROLE_PLATFORM_ADMIN, etc.
	Scopes         []string `json:"scopes"`          // admin:users:read, etc.
	Locale         string   `json:"locale"`          // "es-CR"
	IdempotencyKey string   `json:"idempotency_key"` // Key for idempotency

	// Extended fields for v2 JWT with permissions system
	Metadata map[string]interface{} `json:"-"` // Not serialized, used internally for assignments, etc.
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

	if required == "false" || required == "0" {
		return false
	}

	if required == "true" || required == "1" {
		return true
	}

	return true
}

// Context key para IAMContext
type iamContextKey struct{}

// IAMContextKey es la clave para obtener IAMContext del contexto
var IAMContextKey = &iamContextKey{}

// extractIAMClaimsFromRequest extrae y valida los claims IAM del JWT en el Authorization header
func extractIAMClaimsFromRequest(c echo.Context) (*IAMClaims, error) {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		fmt.Println("IAM Auth - Authorization header missing", "url", c.Request().URL.Path)
		return nil, fmt.Errorf("authorization header missing")
	}

	// Extraer el token (Bearer <token>)
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		fmt.Println("IAM Auth - Invalid authorization header format", "header", authHeader[:min(50, len(authHeader))]+"...")
		return nil, fmt.Errorf("invalid authorization header format")
	}

	tokenString := parts[1]

	// Log del token (primeros 50 caracteres por seguridad)
	tokenPreview := tokenString
	if len(tokenString) > 50 {
		tokenPreview = tokenString[:50] + "..."
	}
	fmt.Printf("IAM Auth - Token received: %s\n", tokenPreview)

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
		fmt.Println("IAM Auth - Failed to parse token", "error", err.Error())
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		fmt.Println("IAM Auth - Token validation failed")
		return nil, fmt.Errorf("invalid token")
	}

	// Extraer claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Log de todos los claims raw del token
	fmt.Println("=== JWT CLAIMS RAW ===")
	for key, value := range claims {
		fmt.Printf("%s: %v\n", key, value)
	}
	fmt.Println("=======================")

	// Validar issuer (iss)
	expectedIssuer := GetIAMJWTIssuer()
	if issuer, ok := claims["iss"].(string); ok {
		if issuer != expectedIssuer {
			fmt.Println("IAM Auth - Invalid issuer", "expected", expectedIssuer, "got", issuer)
			return nil, fmt.Errorf("IAM_INVALID_ISSUER: expected %s, got %s", expectedIssuer, issuer)
		}
	} else {
		fmt.Println("IAM Auth - Missing issuer claim")
		return nil, fmt.Errorf("IAM_INVALID_ISSUER: missing issuer (iss) claim")
	}

	// Validar audience (aud)
	expectedAudience := GetIAMJWTAudience()
	if audience, ok := claims["aud"].(string); ok {
		if audience != expectedAudience {
			fmt.Println("IAM Auth - Invalid audience", "expected", expectedAudience, "got", audience)
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

	// Log detallado de todos los claims extraídos del token
	fmt.Println("=== IAM TOKEN CLAIMS EXTRAÍDOS ===")
	fmt.Printf("Sub: %s\n", iamClaims.Sub)
	fmt.Printf("SubjectKind: %s\n", iamClaims.SubjectKind)
	fmt.Printf("UserType: %s\n", iamClaims.UserType)
	fmt.Printf("CountryCode: %s\n", iamClaims.CountryCode)
	fmt.Printf("Channel: %s\n", iamClaims.Channel)
	fmt.Printf("Locale: %s\n", iamClaims.Locale)
	fmt.Printf("Roles: %v\n", iamClaims.Roles)
	fmt.Printf("Scopes: %v\n", iamClaims.Scopes)
	fmt.Printf("TenantID: %v\n", iamClaims.TenantID)
	fmt.Printf("IdempotencyKey: %s\n", iamClaims.IdempotencyKey)
	fmt.Println("===================================")

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

		logger.LogInfo(fmt.Sprintf("URL Path: %s", c.Request().URL.Path), c.Request())

		excludeJWTPaths := []string{
			"/api/accounting/healthz",
			"/api/admin/healthz",
			"/api/admin/iam/auth/login",
			"/api/customer/healthz",
			"/api/issuer/healthz",
			"/api/transaction/healthz",
		}

		iamCtx := &IAMContext{}

		jwtRequired := GetJWTRequired()

		if !slices.Contains(excludeJWTPaths, c.Request().URL.Path) && jwtRequired {

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
			iamCtx = buildIAMContext(claims)

			// También guardar IAMClaims en el contexto de Echo para compatibilidad
			c.Set("iam_claims", claims)

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

			logger.LogInfo(fmt.Sprintf("validateJWT: %v", validateJWT), c.Request())
			logger.LogInfo(fmt.Sprintf("jwtRequired: %v", jwtRequired), c.Request())
			logger.LogInfo(fmt.Sprintf("currentIdempotencyKey: %s", currentIdempotencyKey), c.Request())
			logger.LogInfo(fmt.Sprintf("claims.IdempotencyKey: %s", claims.IdempotencyKey), c.Request())

			if validateJWT {

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
		fmt.Println("IAM Auth - Setting IAM context in request")
		ctx := context.WithValue(c.Request().Context(), IAMContextKey, iamCtx)
		c.SetRequest(c.Request().WithContext(ctx))
		fmt.Println("IAM Auth - IAMClaims set in Echo context, calling next handler")

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

// ===== NUEVO SISTEMA DE PERMISOS (JWT v2) =====

// RequirePerm valida que el usuario tenga el permiso requerido
func RequirePerm(requiredPerm string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			// Verificar si tiene el permiso requerido
			if !iamCtx.HasScope(requiredPerm) {
				// Platform admin tiene todos los permisos
				if iamCtx.UserType != "platform_admin" {
					logAuthorizationDenied(c, "INSUFFICIENT_PERMISSIONS", fmt.Sprintf("Required permission: %s", requiredPerm))
					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"success": false,
						"error": map[string]interface{}{
							"code":    "AUTHORIZATION_FAILED",
							"message": "Insufficient permissions",
							"detail":  "Required permission: " + requiredPerm,
						},
					})
				}
			}

			return next(c)
		}
	}
}

// RequirePermWithService valida permisos usando un servicio que consulta BD
func RequirePermWithService(permService PermissionService, requiredPerm string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			// Verificar si el permiso es sensible consultando el servicio
			isSensitive, err := permService.IsPermissionSensitive(c.Request().Context(), requiredPerm)
			if err != nil {
				// Si no puede verificar, asumir no sensible y continuar
				isSensitive = false
			}

			if isSensitive {
				// Verificar que el usuario tenga un rol que permita acceder a permisos sensibles
				if iamCtx.UserType != "platform_admin" && iamCtx.UserType != "treasury_approver" {
					logAuthorizationDenied(c, "INSUFFICIENT_PERMISSIONS_FOR_SENSITIVE", fmt.Sprintf("Required permission: %s", requiredPerm))
					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"success": false,
						"error": map[string]interface{}{
							"code":    "AUTHORIZATION_FAILED",
							"message": "Insufficient permissions for sensitive operation",
							"detail":  "This operation requires treasury_approver or platform_admin role",
						},
					})
				}
			}

			// Verificar si tiene el permiso requerido
			if !iamCtx.HasScope(requiredPerm) {
				// Platform admin tiene todos los permisos
				if iamCtx.UserType != "platform_admin" {
					logAuthorizationDenied(c, "INSUFFICIENT_PERMISSIONS", fmt.Sprintf("Required permission: %s", requiredPerm))
					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"success": false,
						"error": map[string]interface{}{
							"code":    "AUTHORIZATION_FAILED",
							"message": "Insufficient permissions",
							"detail":  "Required permission: " + requiredPerm,
						},
					})
				}
			}

			return next(c)
		}
	}
}

// RequireAnyPerm valida que el usuario tenga al menos uno de los permisos requeridos
func RequireAnyPerm(requiredPerms ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			// Platform admin tiene todos los permisos
			if iamCtx.UserType == "platform_admin" {
				return next(c)
			}

			// Verificar si tiene al menos uno de los permisos requeridos
			for _, requiredPerm := range requiredPerms {
				if iamCtx.HasScope(requiredPerm) {
					// Para esta versión básica, no verificamos permisos sensibles
					// Usar RequireAnyPermWithService para validación completa
					return next(c)
				}
			}

			logAuthorizationDenied(c, "INSUFFICIENT_PERMISSIONS", fmt.Sprintf("Required one of: %v", requiredPerms))
			return c.JSON(http.StatusForbidden, map[string]interface{}{
				"success": false,
				"error": map[string]interface{}{
					"code":    "AUTHORIZATION_FAILED",
					"message": "Insufficient permissions",
					"detail":  "Required one of: " + strings.Join(requiredPerms, ", "),
				},
			})
		}
	}
}

// RequireAnyPermWithService valida permisos múltiples usando servicio BD
func RequireAnyPermWithService(permService PermissionService, requiredPerms ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			iamCtx, err := GetIAMContext(c)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			// Platform admin tiene todos los permisos
			if iamCtx.UserType == "platform_admin" {
				return next(c)
			}

			// Verificar si tiene al menos uno de los permisos requeridos
			for _, requiredPerm := range requiredPerms {
				if iamCtx.HasScope(requiredPerm) {
					// Verificar si es sensible consultando el servicio
					isSensitive, err := permService.IsPermissionSensitive(c.Request().Context(), requiredPerm)
					if err != nil {
						isSensitive = false
					}

					if isSensitive && iamCtx.UserType != "treasury_approver" {
						continue
					}
					return next(c)
				}
			}

			logAuthorizationDenied(c, "INSUFFICIENT_PERMISSIONS", fmt.Sprintf("Required one of: %v", requiredPerms))
			return c.JSON(http.StatusForbidden, map[string]interface{}{
				"success": false,
				"error": map[string]interface{}{
					"code":    "AUTHORIZATION_FAILED",
					"message": "Insufficient permissions",
					"detail":  "Required one of: " + strings.Join(requiredPerms, ", "),
				},
			})
		}
	}
}

// ===== INTERFACES PARA SERVICIOS DE PERMISOS =====

// PermissionCache represents cached permission and role data
type PermissionCache struct {
	Permissions map[string]PermissionDTO `json:"permissions"`
	Roles       map[string]RoleDTO       `json:"roles"`
	UpdatedAt   string                   `json:"updated_at"`
}

// PermissionDTO represents a permission in DTO format
type PermissionDTO struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Domain      string `json:"domain"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IsSensitive bool   `json:"is_sensitive"`
}

// RoleDTO represents a role in DTO format
type RoleDTO struct {
	ID          string          `json:"id"`
	Code        string          `json:"code"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	IsSystem    bool            `json:"is_system"`
	Permissions []PermissionDTO `json:"permissions"`
}

// PermissionService defines the interface for permission services
// This should be implemented by services that need database access
type PermissionService interface {
	// GetPermissionCache retrieves cached permission and role data
	GetPermissionCache(ctx context.Context) (*PermissionCache, error)

	// IsPermissionSensitive checks if a permission is sensitive
	IsPermissionSensitive(ctx context.Context, permissionCode string) (bool, error)

	// GetPermissionsForRole retrieves permissions for a specific role
	GetPermissionsForRole(ctx context.Context, roleCode string) ([]string, error)

	// GetPermissionsForRoles retrieves permissions for multiple roles
	GetPermissionsForRoles(ctx context.Context, roleCodes []string) ([]string, error)
}

// ===== FUNCIONES PARA CONSULTAR PERMISOS DESDE REDIS (SIN DEPENDENCIA DE BD) =====

// PermissionCacheRedis representa la estructura de cache de permisos en Redis
// Compatible con la estructura usada en admin-core
type PermissionCacheRedis struct {
	Permissions map[string]PermissionDTORedis `json:"permissions"`
	Roles       map[string]RoleDTORedis       `json:"roles"`
	RoleMapping map[string][]string           `json:"role_mapping"` // Mapeo: assignment.role -> system roles
	UpdatedAt   string                        `json:"updated_at"`   // ISO 8601 string
}

// PermissionDTORedis representa un permiso en el cache Redis
type PermissionDTORedis struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Domain      string `json:"domain"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IsSensitive bool   `json:"is_sensitive"`
}

// RoleDTORedis representa un rol en el cache Redis
type RoleDTORedis struct {
	ID          string               `json:"id"`
	Code        string               `json:"code"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	IsSystem    bool                 `json:"is_system"`
	Permissions []PermissionDTORedis `json:"permissions"`
}

// ===== ESTRUCTURAS DE CACHE DE PERMISOS =====

// PermissionCacheLocal representa la estructura de cache de permisos en Redis
// Compatible con la estructura usada en admin-core
type PermissionCacheLocal struct {
	Permissions map[string]PermissionDTOLocal `json:"permissions"`
	Roles       map[string]RoleDTOLocal       `json:"roles"`
	RoleMapping map[string][]string           `json:"role_mapping"` // Mapeo: assignment.role -> system roles
	UpdatedAt   time.Time                     `json:"updated_at"`
}

// PermissionDTOLocal representa un permiso en el cache Redis
type PermissionDTOLocal struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Domain      string `json:"domain"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IsSensitive bool   `json:"is_sensitive"`
}

// RoleDTOLocal representa un rol en el cache Redis
type RoleDTOLocal struct {
	ID          string               `json:"id"`
	Code        string               `json:"code"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	IsSystem    bool                 `json:"is_system"`
	Permissions []PermissionDTOLocal `json:"permissions"`
}

// IsPermissionSensitive verifica si un permiso es sensible consultando Redis cache directamente
// Esta función puede ser usada por cualquier microservicio sin necesidad de llamar a admin-core
// Parámetros:
//   - permissionCode: Código del permiso a verificar (ej: "transaction.payment.reverse")
//
// Retorna:
//   - bool: true si el permiso es sensible, false si no lo es o no se encuentra
//
// Nota: Esta función usa redis.Rdb directamente del paquete redis de multipay-libs
func IsPermissionSensitive(permissionCode string) bool {
	// Verificar que Redis esté inicializado
	if redis.Rdb == nil {
		// Si Redis no está inicializado, retornar false (no sensible) para no bloquear
		return false
	}

	// Consultar cache Redis compartido
	cacheKey := "permissions_cache"
	cachedData, err := redis.GetUniversalCacheTyped[PermissionCacheLocal](redis.Rdb, cacheKey)
	if err != nil {
		// Si no hay cache, retornar false (no sensible) para no bloquear
		// Esto puede ocurrir si el cache no está inicializado aún
		return false
	}

	permission, exists := cachedData.Permissions[permissionCode]
	if !exists {
		// Si el permiso no existe en cache, retornar false
		return false
	}

	return permission.IsSensitive
}

// IsPermissionSensitiveFromRedis verifica si un permiso es sensible consultando Redis directamente
// DEPRECATED: Usar IsPermissionSensitive en su lugar
// Esta función se mantiene por compatibilidad pero usa IsPermissionSensitive internamente
func IsPermissionSensitiveFromRedis(rdb interface{}, permissionCode string) (bool, error) {
	return IsPermissionSensitive(permissionCode), nil
}

// ===== ASSIGNMENT CLAIM Y FUNCIONES JWT V2 =====
// TODO: Mover a multipay-libs/iam - Estas estructuras y funciones deben estar en la librería compartida

// AssignmentClaim representa un assignment en el JWT v2
// Esta estructura debe estar en multipay-libs/iam para ser compartida entre microservicios
type AssignmentClaim struct {
	ID          string   `json:"id"`           // UUID del assignment
	TenantID    *string  `json:"tenant_id"`    // UUID del tenant (opcional)
	CountryCode string   `json:"country_code"` // Código del país
	PartnerID   *string  `json:"partner_id"`   // UUID del partner (opcional)
	Roles       []string `json:"roles"`        // Roles del assignment
	Perms       []string `json:"perms"`        // Permisos del assignment (derivados de roles)
}

// ExtractAssignmentsFromToken extrae assignments[] del token JWT parseado
// Esta función debe estar en multipay-libs/iam para ser compartida
func ExtractAssignmentsFromToken(tokenClaims map[string]interface{}) ([]AssignmentClaim, error) {
	assignmentsInterface, ok := tokenClaims["assignments"].([]interface{})
	if !ok {
		return nil, nil
	}

	var assignments []AssignmentClaim
	for _, ai := range assignmentsInterface {
		assignmentMap, ok := ai.(map[string]interface{})
		if !ok {
			continue
		}

		assignment := AssignmentClaim{}

		if id, ok := assignmentMap["id"].(string); ok {
			assignment.ID = id
		}
		if tenantID, ok := assignmentMap["tenant_id"].(string); ok {
			assignment.TenantID = &tenantID
		}
		if countryCode, ok := assignmentMap["country_code"].(string); ok {
			assignment.CountryCode = countryCode
		}
		if partnerID, ok := assignmentMap["partner_id"].(string); ok {
			assignment.PartnerID = &partnerID
		}

		if roles, ok := assignmentMap["roles"].([]interface{}); ok {
			assignment.Roles = make([]string, len(roles))
			for i, r := range roles {
				if role, ok := r.(string); ok {
					assignment.Roles[i] = role
				}
			}
		}

		if perms, ok := assignmentMap["perms"].([]interface{}); ok {
			assignment.Perms = make([]string, len(perms))
			for i, p := range perms {
				if perm, ok := p.(string); ok {
					assignment.Perms[i] = perm
				}
			}
		}

		assignments = append(assignments, assignment)
	}

	return assignments, nil
}

// GetActiveAssignmentID extrae el assignment_id activo del token
// Esta función debe estar en multipay-libs/iam para ser compartida
func GetActiveAssignmentID(tokenClaims map[string]interface{}) string {
	active, ok := tokenClaims["active"].(map[string]interface{})
	if !ok {
		return ""
	}

	assignmentID, ok := active["assignment_id"].(string)
	if !ok {
		return ""
	}

	return assignmentID
}

// ===== REQUIRE PERM DB - MIDDLEWARE DE AUTORIZACIÓN =====

// RequirePermDB valida que el usuario tenga el permiso requerido usando Redis cache
// Esta función no requiere gorm.DB, solo usa Redis para consultar permisos sensibles
// Parámetros:
//   - requiredPerm: Código del permiso requerido (ej: "transaction.payment.create")
//
// Retorna:
//   - echo.MiddlewareFunc: Middleware que valida el permiso
//
// Comportamiento:
//   - Si JWT_REQUIRED=false, permite acceso sin validación (útil para desarrollo)
//   - Si JWT_REQUIRED=true, valida que el usuario tenga el permiso en sus claims
//   - Valida permisos sensibles (requieren treasury_approver o platform_admin)
//   - platform_admin tiene acceso a todos los permisos
func RequirePermDB(requiredPerm string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Verificar si JWT es requerido - si no, permitir acceso sin validación
			if !GetJWTRequired() {
				return next(c)
			}

			// Extraer claims IAM del contexto (establecido por IAMAuthMiddleware)
			claims, ok := c.Get("iam_claims").(*IAMClaims)
			if !ok || claims == nil {
				fmt.Println("RequirePermDB - IAM claims not found in Echo context")
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			// Verificar si el permiso es sensible consultando Redis
			if IsPermissionSensitive(requiredPerm) {
				// Verificar que el usuario tenga un rol que permita acceder a permisos sensibles
				userType := claims.UserType
				if userType != "platform_admin" && userType != "treasury_approver" {
					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"success": false,
						"error": map[string]interface{}{
							"code":    "AUTHORIZATION_FAILED",
							"message": "Insufficient permissions for sensitive operation",
							"detail":  "This operation requires treasury_approver or platform_admin role",
						},
					})
				}
			}

			// Obtener permisos del assignment activo
			// En JWT v2, los permisos están en perms[] o scopes[]
			perms := claims.Scopes // Scopes contiene los permisos del assignment activo

			// Verificar si tiene el permiso requerido
			hasPermission := false
			for _, perm := range perms {
				if perm == requiredPerm {
					hasPermission = true
					break
				}
			}

			// Si no tiene el permiso, verificar si tiene platform_admin (todos los permisos)
			if !hasPermission {
				userType := claims.UserType
				if userType == "platform_admin" {
					hasPermission = true
				}
			}

			if !hasPermission {
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "Insufficient permissions",
						"detail":  "Required permission: " + requiredPerm,
					},
				})
			}

			return next(c)
		}
	}
}

// RequireAnyPermDB valida que el usuario tenga al menos uno de los permisos requeridos
// Parámetros:
//   - requiredPerms: Lista de códigos de permisos (al menos uno debe estar presente)
//
// Retorna:
//   - echo.MiddlewareFunc: Middleware que valida al menos uno de los permisos
func RequireAnyPermDB(requiredPerms ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Verificar si JWT es requerido - si no, permitir acceso sin validación
			if !GetJWTRequired() {
				return next(c)
			}

			claims, ok := c.Get("iam_claims").(*IAMClaims)
			if !ok || claims == nil {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error": map[string]interface{}{
						"code":    "AUTHORIZATION_FAILED",
						"message": "IAM claims not found in context",
					},
				})
			}

			perms := claims.Scopes
			userType := claims.UserType

			// platform_admin tiene todos los permisos
			if userType == "platform_admin" {
				return next(c)
			}

			// Verificar si tiene al menos uno de los permisos requeridos
			for _, requiredPerm := range requiredPerms {
				for _, perm := range perms {
					if perm == requiredPerm {
						// Verificar si es sensible
						if IsPermissionSensitive(requiredPerm) && userType != "treasury_approver" {
							continue
						}
						return next(c)
					}
				}
			}

			return c.JSON(http.StatusForbidden, map[string]interface{}{
				"success": false,
				"error": map[string]interface{}{
					"code":    "AUTHORIZATION_FAILED",
					"message": "Insufficient permissions",
					"detail":  "Required one of: " + strings.Join(requiredPerms, ", "),
				},
			})
		}
	}
}
