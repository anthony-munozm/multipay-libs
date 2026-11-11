package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

type MicroserviceClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

type RequestOptions struct {
	Method  string
	Path    string
	Body    interface{}
	Headers http.Header
	Timeout time.Duration
}

type Response struct {
	StatusCode int
	Body       interface{}
	Headers    http.Header
	Error      error
}

var MicroserviceC *MicroserviceClient

const headerServerlessAuthorization = "X-Serverless-Authorization"

// idTokenTransport mints a Google Cloud ID token (ADC / Cloud Run SA metadata)
// and sets X-Serverless-Authorization so Cloud Run IAM can authenticate the hop
// without overwriting an application Authorization Bearer (Multipay IAM JWT).
type idTokenTransport struct {
	base     http.RoundTripper
	audience string

	mu sync.Mutex
	ts oauth2.TokenSource
}

func (t *idTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	ts, err := t.tokenSource(req.Context())
	if err != nil {
		return nil, fmt.Errorf("bridge: id token source (audience=%s): %w", t.audience, err)
	}
	token, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("bridge: id token fetch (audience=%s): %w", t.audience, err)
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return nil, fmt.Errorf("bridge: empty id token (audience=%s)", t.audience)
	}

	req2 := req.Clone(req.Context())
	req2.Header.Set(headerServerlessAuthorization, "Bearer "+token.AccessToken)
	return base.RoundTrip(req2)
}

func (t *idTokenTransport) tokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ts != nil {
		return t.ts, nil
	}
	ts, err := idtoken.NewTokenSource(ctx, t.audience)
	if err != nil {
		return nil, err
	}
	t.ts = ts
	return ts, nil
}

// cloudRunAudience returns scheme://host for HTTPS Cloud Run targets that need IAM auth.
// Localhost, plain HTTP, and empty URLs skip ID token injection.
func cloudRunAudience(rawURL string) (string, bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func newHTTPClient(baseURL string) *http.Client {
	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	if audience, ok := cloudRunAudience(baseURL); ok {
		client.Transport = &idTokenTransport{
			base:     http.DefaultTransport,
			audience: audience,
		}
	}
	return client
}

func NewMicroserviceClient() *MicroserviceClient {
	baseURL := os.Getenv("GATEWAY_URL")
	if baseURL == "" {
		baseURL = "https://11859073a800.ngrok-free.app"
	}

	MicroserviceC = &MicroserviceClient{
		BaseURL:    baseURL,
		HTTPClient: newHTTPClient(baseURL),
	}
	return MicroserviceC
}

// client := NewMicroserviceClient("http://localhost:8081/api")
// return client.CallAdapterSinpe("POST", "/AcreditarCuenta", creditData, nil)

func (mc *MicroserviceClient) CallMicroservice(options RequestOptions) interface{} {
	response := func() *Response {
		fullURL := fmt.Sprintf("%s%s", mc.BaseURL, options.Path)
		var body io.Reader
		if options.Body != nil {
			jsonBody, err := json.Marshal(options.Body)
			if err != nil {
				return &Response{
					StatusCode: 0,
					Error:      fmt.Errorf("error marshaling request body: %w", err),
				}
			}
			body = bytes.NewBuffer(jsonBody)
		}

		req, err := http.NewRequest(options.Method, fullURL, body)
		if err != nil {
			return &Response{
				StatusCode: 0,
				Error:      fmt.Errorf("error creating request: %w", err),
			}
		}

		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}

		req.Header.Set("X-Internal-Request", "true")

		if options.Headers != nil {
			for key, values := range options.Headers {
				for _, value := range values {
					if key != "Idempotency-Key" {
						// Use Set() for headers that should only have one value
						// Use Add() for headers that can have multiple values
						if key == "Content-Type" || key == "Accept" {
							req.Header.Set(key, value)
						} else {
							req.Header.Add(key, value)
						}
					}
				}
			}
		}

		if options.Timeout > 0 {
			mc.HTTPClient.Timeout = options.Timeout
		}

		resp, err := mc.HTTPClient.Do(req)
		if err != nil {
			return &Response{
				StatusCode: 0,
				Error:      fmt.Errorf("error making request: %w", err),
			}
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return &Response{
				StatusCode: resp.StatusCode,
				Error:      fmt.Errorf("error reading response body: %w", err),
			}
		}

		return &Response{
			StatusCode: resp.StatusCode,
			Body:       respBody,
			Headers:    resp.Header,
			Error:      nil,
		}
	}()

	var responseObj interface{}
	if response != nil && response.Error == nil {
		if response.Body != nil {
			if bodyBytes, ok := response.Body.([]byte); ok {
				if err := json.Unmarshal(bodyBytes, &responseObj); err != nil {
					responseObj = map[string]interface{}{
						"error": "invalid json",
						"raw":   string(bodyBytes),
					}
				}
			} else {
				responseObj = map[string]interface{}{
					"error": "unexpected body type",
					"body":  response.Body,
				}
			}
		} else {
			responseObj = map[string]interface{}{
				"status_code": response.StatusCode,
				"message":     "No body in response",
			}
		}
	} else if response != nil && response.Error != nil {
		responseObj = map[string]interface{}{
			"error": response.Error.Error(),
		}
	} else {
		responseObj = map[string]interface{}{
			"error": "No response from microservice",
		}
	}

	return responseObj
}

func (mc *MicroserviceClient) CallAdapterSinpe(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/adapter/sinpe/IEntidadXBS%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallAdminCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/api/admin%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallIssuerCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/api/issuer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallCustomerCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/api/customer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallAccountingCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/api/accounting%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallTransactionCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/api/transaction%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}
