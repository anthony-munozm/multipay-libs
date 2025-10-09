package redisad

import (
  "encoding/json"
  "fmt"
  "time"
  "github.com/redis/go-redis/v9"
  "context"
  "log"
  "github.com/google/uuid"
)

type SettingsDTO struct {
	ID        uuid.UUID       `json:"id"`
	Key      string          `json:"key"`
  Value      interface{}          `json:"value"`
  ValueType  string          `json:"value_type"`
  Scope  string          `json:"scope"`
  TargetID  string          `json:"target_id"`
  ValidFrom  time.Time          `json:"valid_from"`
  ValidTo  time.Time          `json:"valid_to"`
  Version  int          `json:"version"`
  Description  string          `json:"description"`
  CreatedBy  string          `json:"created_by"`
	IsActive   bool            `json:"is_active"`
  Metadata  json.RawMessage          `json:"metadata"`
  CreatedAt time.Time       `json:"created_at"`
  UpdatedAt time.Time       `json:"updated_at"`
}

var Rdb *redis.Client

func NewRedisClient(redisURL string, password string, db int) *redis.Client {
    rdb := redis.NewClient(&redis.Options{
        Addr:     redisURL,
        Password: password,
        DB:       db,
    })
    Rdb = rdb
    return Rdb
}

func SaveSettingsList(rdb *redis.Client, microservice string, configs []SettingsDTO) {
    key := fmt.Sprintf("config:%s", microservice)

    jsonData, err := json.Marshal(configs)
    if err != nil {
      log.Println("Error creando lista", err)
    }

    err = rdb.Set(context.Background(), key, jsonData, time.Hour).Err()
    if err != nil {
      log.Println("Error guardando lista", err)
    }

    log.Println("Lista de configuraciones guardada")
}

func SaveUniversalCache(rdb *redis.Client, key string, data interface{}, ttl time.Duration) {
  jsonData, err := json.Marshal(data)
  if err != nil {
    log.Println("Error creando lista", err)
  }

  if ttl == 0 {
    ttl = time.Hour
  }

  err = rdb.Set(context.Background(), key, jsonData, ttl).Err()
  if err != nil {
    log.Println("Error guardando lista", err)
  }

  log.Println("Lista de configuraciones guardada")
}

func GetUniversalCacheTyped[T any](rdb *redis.Client, key string) (T, error) {
  var result T
  val, err := rdb.Get(context.Background(), key).Result()
  if err != nil {
    return result, err
  }

  err = json.Unmarshal([]byte(val), &result)
  if err != nil {
    return result, fmt.Errorf("error unmarshaling cached data: %w", err)
  }

  return result, nil
}

func GetSettingsList(rdb *redis.Client, microservice string) []SettingsDTO {
    key := fmt.Sprintf("config:%s", microservice)

    val, err := rdb.Get(context.Background(), key).Result()
    if err != nil {
        if err == redis.Nil {
          log.Println("No existe configuración")
            return nil
        }
        log.Println("Error leyendo lista", err)
    }

    var configs []SettingsDTO
    err = json.Unmarshal([]byte(val), &configs)
    if err != nil {
      log.Println("Error parseando lista", err)
    }

    return configs
}