package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
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

func NewMicroserviceClient() *MicroserviceClient {
	baseURL := os.Getenv("GATEWAY_URL")
	if baseURL == "" {
		baseURL = "https://11859073a800.ngrok-free.app/api"
	}

	MicroserviceC = &MicroserviceClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	return MicroserviceC
}

// client := NewMicroserviceClient("http://localhost:8081/api")
// return client.CallAdapterSinpe("POST", "/AcreditarCuenta", creditData, nil)

func (mc *MicroserviceClient) CallMicroservice(options RequestOptions) interface{} {
	response := func() *Response {
		fullURL := fmt.Sprintf("%s%s", mc.BaseURL, options.Path)
		log.Println("ID0004")
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

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		if options.Headers != nil {
			for key, values := range options.Headers {
				for _, value := range values {
					req.Header.Add(key, value)
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
					responseObj = string(bodyBytes)
				}
			} else {
				responseObj = response.Body
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

func CallAdapterSinpe(method, path string, body interface{}, headers http.Header) interface{} {
	mc := NewMicroserviceClient()
	fullPath := fmt.Sprintf("/adapter/sinpe/IEntidadXBS%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func CallAdminCore(method, path string, body interface{}, headers http.Header) interface{} {
	mc := NewMicroserviceClient()
	fullPath := fmt.Sprintf("/admin%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func CallIssuerCore(method, path string, body interface{}, headers http.Header) interface{} {
	mc := NewMicroserviceClient()
	fullPath := fmt.Sprintf("/issuer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func CallCustomerCore(method, path string, body interface{}, headers http.Header) interface{} {
	mc := NewMicroserviceClient()
	fullPath := fmt.Sprintf("/customer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}
