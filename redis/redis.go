package redis

import (
  "encoding/json"
  "fmt"
  "time"
  "github.com/redis/go-redis/v9"
  "context"
  "log"
  "github.com/anthony-munozm/multipay-libs/bridge"
)

var Rdb *redis.Client

type UniversalCache struct {
  Key string `json:"key"`
  Data interface{} `json:"data"`
  Expiration time.Duration `json:"expiration"`
}

func NewRedisClient(redisURL string, password string, db int) *redis.Client {
    rdb := redis.NewClient(&redis.Options{
        Addr:     redisURL,
        Password: password,
        DB:       db,
    })
    Rdb = rdb
    return Rdb
}

func SaveSettingsList(rdb *redis.Client, microservice string, configs []map[string]interface{}, ttl time.Duration) {
    key := fmt.Sprintf("config:%s", microservice)

    jsonData, err := json.Marshal(configs)
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

func GetCacheByMicroservice(rdb *redis.Client, microservice string) []byte {
  key := fmt.Sprintf("config:%s", microservice)

  log.Println("key", key)

  val, err := rdb.Get(context.Background(), key).Result()
  if err != nil {
      if err == redis.Nil {
        log.Println("No existe configuración")
          return nil
      }
      log.Println("Error leyendo lista", err)
      return nil
  }

  return []byte(val)
}

func GetSettingsList(rdb *redis.Client, microservice string, settingsVersion string) []map[string]interface{} {
    val := GetCacheByMicroservice(rdb, microservice)
    if val == nil {
      return nil
    }

    var configs []map[string]interface{}
    err := json.Unmarshal(val, &configs)
    if err != nil {
      log.Println("Error parseando lista", err)
      return nil
    }

    cleanConfigs := []map[string]interface{}{}

    for _, config := range configs {
      version, exists := config["version"];
      if exists {
        versionStr := fmt.Sprintf("%v", version)
        if versionStr == settingsVersion { 
          log.Println("Versiones iguales")
          cleanConfigs = append(cleanConfigs, config)
        }
      }
    }

    return cleanConfigs
}

func GetSetting(rdb *redis.Client, microservice string, settingKey string, settingsVersion string) interface{} {
  val := GetCacheByMicroservice(rdb, microservice)
  if val == nil {
    return nil
  }

  var configs []map[string]interface{}
  err := json.Unmarshal(val, &configs)
  if err != nil {
    log.Println("Error parseando lista", err)
    return nil
  }

  for _, config := range configs {
    version, existsV := config["version"];
    if existsV  {
      key, existskey := config["key"];
      if existskey {
        versionStr := fmt.Sprintf("%v", version)
        if versionStr == settingsVersion && key == settingKey { 
          return config["value"]
        }
      }
    }
  }

  log.Println("No existe configuración")
  return nil
}

func GetSettingEntersByKey(rdb *redis.Client, microservice string, settingKey string, settingsVersion string, entersKey []string) interface{} {
  setting := GetSetting(rdb, microservice, settingKey, settingsVersion)
  if setting == nil {
    return nil
  }
  
  settingMap, ok := setting.(map[string]interface{})
  if !ok {
    return nil
  }
  
  current := settingMap
  for _, key := range entersKey {
    currentValue, exists := current[key]
    if !exists {
      return nil
    }
    
    if currentMap, ok := currentValue.(map[string]interface{}); ok {
      current = currentMap
    } else {
      return currentValue
    }
  }
  
  return nil
}

func UpdateSettingsList(rdb *redis.Client, microservice string, ttl time.Duration) { 
  settings := bridge.NewMicroserviceClient().CallAdminCore("GET", "/settings", nil, nil)
  if settingsMap, ok := settings.(map[string]interface{}); ok {
    if success, exists := settingsMap["success"]; exists && success == true {
      key := fmt.Sprintf("config:%s", microservice)
      jsonData, err := json.Marshal(settingsMap["response"])
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
    }
  }
}