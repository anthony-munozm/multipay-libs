package otel

import (
	"context"
	"log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func InitTracer(ctx context.Context) func() {
    exporter, err := otlptrace.New(context.Background(), otlptracehttp.NewClient())
    if err != nil {
   		log.Fatalf("error initializing tracer: %v", err)
    }

    tp := sdktrace.NewTracerProvider(
   	 sdktrace.WithSampler(sdktrace.AlwaysSample()),
   	 sdktrace.WithBatcher(exporter),
    )
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
    
	return func() {
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("error shutting down tracer provider: %v", err)
		}
	}
}