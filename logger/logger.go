package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"fmt"
	"net/http"
	"github.com/google/uuid"
)

var Logger *zap.Logger

type LogContext struct {
	TraceID string
	CorrelationID string
	Tenant string
	Country string
	Canton string
	RequestID string
	UserID string
	Actor string
}

func NewLogger() *zap.Logger {
	config := zap.NewProductionConfig()
	config.Encoding = "json"
	config.OutputPaths = []string{"stdout"}
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.StacktraceKey = "stacktrace"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	Logger = zap.Must(config.Build())
	return Logger
}

func ExtractLogContext(r *http.Request) LogContext {
	if r == nil {
		return LogContext{
			TraceID: "",
			CorrelationID: "",
			Tenant: "",
			Country: "",
			Canton: "",
			RequestID: uuid.New().String(),
			UserID: "",
			Actor: "",
		}
	}

	var headers http.Header
	if r.Header != nil {
		headers = r.Header
	} else {
		headers = make(http.Header)
	}

	return LogContext{
		TraceID: headers.Get("X-Trace-ID"),
		CorrelationID: headers.Get("X-Correlation-ID"),
		Tenant: headers.Get("X-Tenant-ID"),
		Country: headers.Get("X-Country"),
		Canton: headers.Get("X-Canton"),
		RequestID: uuid.New().String(),
		UserID: headers.Get("X-User-ID"),
		Actor: headers.Get("X-Actor"),
	}
}

func LogInfo(message string, r *http.Request) {
	ctx := ExtractLogContext(r)
	Logger.Info(message,
		zap.String("traceId", ctx.TraceID),
		zap.String("correlationId", ctx.CorrelationID),
		zap.String("tenant", ctx.Tenant),
		zap.String("country", ctx.Country),
		zap.String("canton", ctx.Canton),
		zap.String("requestId", ctx.RequestID),
		zap.String("userId", ctx.UserID),
		zap.String("actor", ctx.Actor),
		zap.String("microservice", "admin-core"),
		zap.String("logging.googleapis.com/trace", fmt.Sprintf("projects/%s/traces/%s", "my-gcp-project", ctx.TraceID)),
	)
	fmt.Println("ID0002")
}

	
	
	
	
	
	
	
	
	
	
	
	
	