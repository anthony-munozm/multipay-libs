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
		log.Println("CALLMICROSERVICE- ID0001 - fullURL: ", fullURL)
		var body io.Reader
		log.Println("CALLMICROSERVICE- ID0002 - body: ", body)
		if options.Body != nil {
			jsonBody, err := json.Marshal(options.Body)
			log.Println("CALLMICROSERVICE- ID0003 - jsonBody: ", jsonBody)
			if err != nil {
				return &Response{
					StatusCode: 0,
					Error:      fmt.Errorf("error marshaling request body: %w", err),
				}
			}
			body = bytes.NewBuffer(jsonBody)
			log.Println("CALLMICROSERVICE- ID0004 - body: ", body)
		}

		req, err := http.NewRequest(options.Method, fullURL, body)
		if err != nil {
			return &Response{
				StatusCode: 0,
				Error:      fmt.Errorf("error creating request: %w", err),
			}
		}

		log.Println("CALLMICROSERVICE- ID0005 - req: ", req)

		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}

		log.Println("CALLMICROSERVICE- ID0006 - req.Header: ", req.Header)

		if options.Headers != nil {
			for key, values := range options.Headers {
				for _, value := range values {
					log.Println(key)
					if key != "Idempotency-Key" {
						req.Header.Add(key, value)
					}
				}
			}
		}

		log.Println("CALLMICROSERVICE- ID0007 - req.Header: ", req.Header)

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
		log.Println("CALLMICROSERVICE- ID0008 - respBody: ", respBody)
		if err != nil {
			return &Response{
				StatusCode: resp.StatusCode,
				Error:      fmt.Errorf("error reading response body: %w", err),
			}
		}

		log.Println("CALLMICROSERVICE- ID0009")

		return &Response{
			StatusCode: resp.StatusCode,
			Body:       respBody,
			Headers:    resp.Header,
			Error:      nil,
		}
	}()

	log.Println("CALLMICROSERVICE- ID0010")

	var responseObj interface{}
	if response != nil && response.Error == nil {
		log.Println("CALLMICROSERVICE- ID0011 - response.Body != nil")
		if response.Body != nil {
			log.Println("CALLMICROSERVICE- ID0012 - response.Body != nil")
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
		log.Println("CALLMICROSERVICE- ID0013 - response.Error != nil")
		responseObj = map[string]interface{}{
			"error": response.Error.Error(),
		}
	} else {
		log.Println("CALLMICROSERVICE- ID0014 - response.Error == nil")
		responseObj = map[string]interface{}{
			"error": "No response from microservice",
		}
	}

	log.Println("CALLMICROSERVICE- ID0015 - responseObj: ", responseObj)

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
	fullPath := fmt.Sprintf("/admin%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallIssuerCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/issuer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallCustomerCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/customer%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallAccountingCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/accounting%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}

func (mc *MicroserviceClient) CallTransactionCore(method, path string, body interface{}, headers http.Header) interface{} {
	fullPath := fmt.Sprintf("/transaction%s", path)
	return mc.CallMicroservice(RequestOptions{
		Method:  method,
		Path:    fullPath,
		Body:    body,
		Headers: headers,
	})
}
