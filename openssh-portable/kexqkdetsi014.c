#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <time.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "digest.h"
#include "kex.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

#define DEFAULT_ENC_SAE_ID ""
#define DEFAULT_DEC_SAE_ID ""
#define QKD_ENC_SAE_ENV "QKD_ENC_SAE_ID"
#define QKD_DEC_SAE_ENV "QKD_DEC_SAE_ID"

#define DEFAULT_ENC_KME ""
#define DEFAULT_DEC_KME ""
#define QKD_ENC_KME_ENV "QKD_ENC_KME"
#define QKD_DEC_KME_ENV "QKD_DEC_KME"

#define STATIC_CREDENTIALS
#define DEFAULT_ENC_IPPORT "host.docker.internal:6600"
#define DEFAULT_DEC_IPPORT "host.docker.internal:6600"
#define QKD_ENC_IPPORT_ENV "QKD_ENC_IPPORT"
#define QKD_DEC_IPPORT_ENV "QKD_DEC_IPPORT"

/* Define constants */
#define QKD_KEY_LENGTH 32

/* Define data structures */
typedef struct {
  uint8_t key_id[QKD_KEY_ID_LENGTH];
  uint8_t key[QKD_KEY_LENGTH];
} QKD_Key;

// ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-

/* Helper struct for storing response data */
struct MemoryStruct {
  char *memory;
  size_t size;
};

/* Helper to check if a file exists */
static bool file_exists(const char *path) {
  return path != NULL && access(path, F_OK) == 0;
}

static const char *get_env_value(const char *env_name, const char *fallback) {
  const char *val = getenv(env_name);
  return (val && *val) ? val : fallback;
}

/* Send key usage metrics to MonDash if enabled */
static void self_report_usage(void) {
  const char *enabled = getenv("SELF_REPORTING");
  if (!(enabled && strcasecmp(enabled, "true") == 0))
    return;

  const char *endpoint = getenv("REPORT_ENDPOINT");
  const char *name = getenv("REPORTING_NAME");
  const char *token = getenv("REPORT_TOKEN");
  const char *trust_str = getenv("REPORT_TRUST_SELF_SIGNED");

  if (endpoint == NULL || *endpoint == '\0')
    return;
  if (name == NULL)
    name = "qssh";
  if (token == NULL)
    token = "";

  char node_id[256];
  if (gethostname(node_id, sizeof(node_id)) != 0) {
    strncpy(node_id, "unknown", sizeof(node_id));
    node_id[sizeof(node_id) - 1] = '\0';
  }

  struct json_object *json = json_object_new_object();
  json_object_object_add(json, "nodeId", json_object_new_string(node_id));
  json_object_object_add(json, "name", json_object_new_string(name));
  json_object_object_add(json, "numberOfKeys", json_object_new_int(1));
  json_object_object_add(json, "keySize",
                         json_object_new_int(QKD_KEY_SIZE * 8));

  const char *post_data = json_object_to_json_string(json);

  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  if (curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "X-Auth-Token: %s", token);
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    if (trust_str && strcasecmp(trust_str, "true") == 0) {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      debug("self_report: curl_easy_perform() failed: %s",
            curl_easy_strerror(res));
    } else {
      debug("self_report: successfully reported usage");
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  json_object_put(json);
  curl_global_cleanup();
}

/* Callback function for handling data received from curl */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL) {
    // Out of memory
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0; // Null-terminate the string

  return realsize;
}

/* Base64 decoding function using OpenSSL */
static int Base64Decode(const char *b64message, unsigned char **buffer,
                        size_t *length) {
  BIO *bio, *b64;
  int decodeLen = strlen(b64message);
  int padding = 0;

  if (b64message[decodeLen - 1] == '=' &&
      b64message[decodeLen - 2] == '=') // Last two chars are '='
    padding = 2;
  else if (b64message[decodeLen - 1] == '=') // Last char is '='
    padding = 1;

  size_t expectedLen = (decodeLen * 3) / 4 - padding;

  *buffer = (unsigned char *)malloc(expectedLen);
  if (*buffer == NULL) {
    return -1;
  }

  bio = BIO_new_mem_buf(b64message, -1);
  if (bio == NULL) {
    free(*buffer);
    return -1;
  }
  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    BIO_free(bio);
    free(*buffer);
    return -1;
  }
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
  *length = BIO_read(bio, *buffer, decodeLen);
  BIO_free_all(bio);

  if (*length != expectedLen) {
    free(*buffer);
    return -1;
  }

  return 0;
}

/* Function to convert UUID string to bytes */
static int UUIDStringToBytes(const char *uuid_str, uint8_t *uuid_bytes) {
  uuid_t uuid;
  if (uuid_parse(uuid_str, uuid) != 0) {
    return -1; // Invalid UUID string
  }
  memcpy(uuid_bytes, uuid, QKD_KEY_ID_LENGTH);
  return 0;
}

/* Function to convert UUID bytes to string */
static void UUIDBytesToString(const uint8_t *uuid_bytes, char *uuid_str) {
  uuid_unparse(uuid_bytes, uuid_str);
}

int qkd_get_key(QKD_Key *key) {
  if (key == NULL) {
    return -1;
  }

  memset(key, 0, sizeof(QKD_Key));

  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;

  chunk.memory = (char *)malloc(1); // Will be grown as needed by realloc
  chunk.size = 0;                   // No data at this point

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  if (curl) {
    const char *qkd_ipport_value =
        get_env_value(QKD_ENC_IPPORT_ENV, DEFAULT_ENC_IPPORT);
    const char *enc_sae = get_env_value(QKD_ENC_SAE_ENV, DEFAULT_ENC_SAE_ID);
    const char *enc_kme = get_env_value(QKD_ENC_KME_ENV, DEFAULT_ENC_KME);
    /* Determine whether certificates are available. If none are
     * provided we fall back to HTTP. This option is intended for
     * testing only and should not be used in production. */
#ifdef STATIC_CREDENTIALS
    const char *ssl_cert = "/certs/qkd.crt";
    const char *ssl_key = "/certs/qkd.key";
    const char *cacert = "/certs/qkd-ca.crt";
#else
    const char *ssl_cert = getenv("QKD_SSL_CERT");
    const char *ssl_key = getenv("QKD_SSL_CERT");
    const char *cacert = getenv("QKD_SSL_CERT");
#endif
    bool have_cert =
        ssl_cert && file_exists(ssl_cert) && ssl_key && file_exists(ssl_key);
    bool have_cacert = cacert && file_exists(cacert);

    const char *scheme = have_cert ? "https" : "http";

    // Set the URL; omit KME component if not specified
    char qkd_url[256];
    if (enc_kme != NULL && *enc_kme != '\0') {
      snprintf(qkd_url, sizeof(qkd_url), "%s://%s/%s/api/v1/keys/%s/enc_keys",
               scheme, qkd_ipport_value, enc_kme, enc_sae);
    } else {
      snprintf(qkd_url, sizeof(qkd_url), "%s://%s/api/v1/keys/%s/enc_keys",
               scheme, qkd_ipport_value, enc_sae);
    }
    curl_easy_setopt(curl, CURLOPT_URL, qkd_url);

    if (have_cert) {
      curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_cert);
      curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_key);
      if (have_cacert) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);
      } else {
        debug("No CA certificate found; proceeding without CAINFO\n");
      }
    } else {
      debug("No certificates found; using HTTP mode\n");
    }

    // Ignore certificate validation errors if needed (equivalent to -k flag)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Set up callback function to capture the response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // Perform the request
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      debug("get_key_from_qkd: curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
      // Handle the error
      curl_easy_cleanup(curl);
      free(chunk.memory);
      curl_global_cleanup();
      return -1;
    } else {
      // Parse the JSON response
      struct json_object *parsed_json;
      struct json_object *keys_array;
      struct json_object *key_obj;
      struct json_object *key_str_obj;
      struct json_object *key_id_obj;

      parsed_json = json_tokener_parse(chunk.memory);
      if (parsed_json == NULL) {
        debug("get_key_from_qkd: Failed to parse JSON response\n");
        // Handle the error
        curl_easy_cleanup(curl);
        free(chunk.memory);
        curl_global_cleanup();
        return -1;
      } else {
        if (json_object_object_get_ex(parsed_json, "keys", &keys_array)) {
          size_t n_keys = json_object_array_length(keys_array);
          if (n_keys > 0) {
            key_obj = json_object_array_get_idx(keys_array, 0);
            if (json_object_object_get_ex(key_obj, "key", &key_str_obj) &&
                json_object_object_get_ex(key_obj, "key_ID", &key_id_obj)) {

              const char *key_b64_str = json_object_get_string(key_str_obj);
              const char *key_id_str = json_object_get_string(key_id_obj);

              // Base64 decode the key
              unsigned char *key_data = NULL;
              size_t key_data_len = 0;
              if (Base64Decode(key_b64_str, &key_data, &key_data_len) == 0) {
                if (key_data_len != QKD_KEY_LENGTH) {
                  debug("get_key_from_qkd: Invalid key length after Base64 "
                        "decoding\n");
                  free(key_data);
                  json_object_put(parsed_json);
                  curl_easy_cleanup(curl);
                  free(chunk.memory);
                  curl_global_cleanup();
                  return -1;
                } else {
                  memcpy(key->key, key_data, QKD_KEY_LENGTH);
                  free(key_data);
                }
              } else {
                debug("get_key_from_qkd: Failed to decode Base64 key\n");
                json_object_put(parsed_json);
                curl_easy_cleanup(curl);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
              }

              // Convert UUID string to bytes
              if (UUIDStringToBytes(key_id_str, key->key_id) != 0) {
                debug("get_key_from_qkd: Failed to convert key_ID to bytes\n");
                json_object_put(parsed_json);
                curl_easy_cleanup(curl);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
              }
            } else {
              debug("get_key_from_qkd: JSON key object does not contain "
                    "expected fields\n");
              json_object_put(parsed_json);
              curl_easy_cleanup(curl);
              free(chunk.memory);
              curl_global_cleanup();
              return -1;
            }
          } else {
            debug("get_key_from_qkd: No keys available in response\n");
            json_object_put(parsed_json);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
          }
        } else {
          debug("get_key_from_qkd: JSON response does not contain 'keys' "
                "array\n");
          json_object_put(parsed_json);
          curl_easy_cleanup(curl);
          free(chunk.memory);
          curl_global_cleanup();
          return -1;
        }

        // Free JSON object
        json_object_put(parsed_json);
      }

      // Clean up
      curl_easy_cleanup(curl);
    }

    // Clean up the memory chunk
    if (chunk.memory) {
      free(chunk.memory);
    }

    curl_global_cleanup();

    return 0; // Success
  } else {
    debug("get_key_from_qkd: curl_easy_init() failed\n");
    curl_global_cleanup();
    return -1;
  }
}

int qkd_get_key_by_id(const uint8_t key_id[QKD_KEY_ID_LENGTH], QKD_Key *key) {
  if (key_id == NULL || key == NULL) {
    return -1;
  }

  memset(key, 0, sizeof(QKD_Key));

  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;

  chunk.memory = (char *)malloc(1); // Will be grown as needed by realloc
  chunk.size = 0;                   // No data at this point

  curl = curl_easy_init();
  if (curl) {
    const char *qkd_ipport_value =
        get_env_value(QKD_DEC_IPPORT_ENV, DEFAULT_DEC_IPPORT);
    const char *dec_sae = get_env_value(QKD_DEC_SAE_ENV, DEFAULT_DEC_SAE_ID);
    const char *dec_kme = get_env_value(QKD_DEC_KME_ENV, DEFAULT_DEC_KME);

    /* Determine whether certificates are available. If none are
     * provided we fall back to HTTP. This option is intended for
     * testing only and should not be used in production. */
#ifdef STATIC_CREDENTIALS
    const char *ssl_cert = "/certs/qkd.crt";
    const char *ssl_key = "/certs/qkd.key";
    const char *cacert = "/certs/qkd-ca.crt";
#else
    const char *ssl_cert = getenv("QKD_SSL_CERT");
    const char *ssl_key = getenv("QKD_SSL_CERT");
    const char *cacert = getenv("QKD_SSL_CERT");
#endif
    bool have_cert =
        ssl_cert && file_exists(ssl_cert) && ssl_key && file_exists(ssl_key);
    bool have_cacert = cacert && file_exists(cacert);

    const char *scheme = have_cert ? "https" : "http";

    // Build the URL; omit KME component if not specified
    char qkd_url[256];
    if (dec_kme != NULL && *dec_kme != '\0') {
      snprintf(qkd_url, sizeof(qkd_url), "%s://%s/%s/api/v1/keys/%s/dec_keys",
               scheme, qkd_ipport_value, dec_kme, dec_sae);
    } else {
      snprintf(qkd_url, sizeof(qkd_url), "%s://%s/api/v1/keys/%s/dec_keys",
               scheme, qkd_ipport_value, dec_sae);
    }
    curl_easy_setopt(curl, CURLOPT_URL, qkd_url);

    if (have_cert) {
      curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_cert);
      curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_key);
      if (have_cacert) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);
      } else {
        debug("No CA certificate found; proceeding without CAINFO\n");
      }
    } else {
      debug("No certificates found; using HTTP mode\n");
    }

    debug("dec keys url: %s", qkd_url);

    // Ignore certificate validation errors if needed (equivalent to -k flag)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Prepare the POST data with key ID
    // Convert key_id (binary data) to UUID string
    char key_id_str[37]; // UUIDs are 36 characters plus null terminator
    uuid_unparse(key_id, key_id_str);

    // Prepare JSON data
    char post_data[256];
    snprintf(post_data, sizeof(post_data),
             "{ \"key_IDs\":[{ \"key_ID\": \"%s\" }] }", key_id_str);

    // Set POST method
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    // Set up callback function to capture the response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // Perform the request
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      debug("get_key_by_id: curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
      // Clean up
      curl_easy_cleanup(curl);
      curl_slist_free_all(headers);
      free(chunk.memory);
      curl_global_cleanup();
      return -1;
    } else {
      // Parse the JSON response
      struct json_object *parsed_json;
      struct json_object *keys_array;
      struct json_object *key_obj;
      struct json_object *key_str_obj;
      struct json_object *key_id_obj;

      parsed_json = json_tokener_parse(chunk.memory);
      if (parsed_json == NULL) {
        debug("get_key_by_id: Failed to parse JSON response\n");
        // Clean up
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(chunk.memory);
        curl_global_cleanup();
        return -1;
      } else {
        if (json_object_object_get_ex(parsed_json, "keys", &keys_array)) {
          size_t n_keys = json_object_array_length(keys_array);
          if (n_keys > 0) {
            key_obj = json_object_array_get_idx(keys_array, 0);
            if (json_object_object_get_ex(key_obj, "key", &key_str_obj) &&
                json_object_object_get_ex(key_obj, "key_ID", &key_id_obj)) {

              const char *key_b64_str = json_object_get_string(key_str_obj);
              const char *key_id_response_str =
                  json_object_get_string(key_id_obj);

              // Base64 decode the key
              unsigned char *key_data = NULL;
              size_t key_data_len = 0;
              if (Base64Decode(key_b64_str, &key_data, &key_data_len) == 0) {
                if (key_data_len != QKD_KEY_LENGTH) {
                  debug("get_key_by_id: Invalid key length after Base64 "
                        "decoding\n");
                  free(key_data);
                  json_object_put(parsed_json);
                  curl_easy_cleanup(curl);
                  curl_slist_free_all(headers);
                  free(chunk.memory);
                  curl_global_cleanup();
                  return -1;
                } else {
                  memcpy(key->key, key_data, QKD_KEY_LENGTH);
                  free(key_data);
                }
              } else {
                debug("get_key_by_id: Failed to decode Base64 key\n");
                json_object_put(parsed_json);
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
              }

              // Convert key_ID in response back to bytes and compare with
              // requested key_id
              uint8_t response_key_id[QKD_KEY_ID_LENGTH];
              if (UUIDStringToBytes(key_id_response_str, response_key_id) !=
                  0) {
                debug("get_key_by_id: Failed to convert response key_ID to "
                      "bytes\n");
                json_object_put(parsed_json);
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
              }
              if (memcmp(response_key_id, key_id, QKD_KEY_ID_LENGTH) != 0) {
                debug("get_key_by_id: Response key_ID does not match requested "
                      "key_ID\n");
                json_object_put(parsed_json);
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
              }
              // Store the key_id
              memcpy(key->key_id, key_id, QKD_KEY_ID_LENGTH);

            } else {
              debug("get_key_by_id: JSON key object does not contain expected "
                    "fields\n");
              json_object_put(parsed_json);
              curl_easy_cleanup(curl);
              curl_slist_free_all(headers);
              free(chunk.memory);
              curl_global_cleanup();
              return -1;
            }
          } else {
            debug("get_key_by_id: No keys available in response\n");
            json_object_put(parsed_json);
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
          }
        } else {
          debug("get_key_by_id: JSON response does not contain 'keys' array\n");
          json_object_put(parsed_json);
          curl_easy_cleanup(curl);
          curl_slist_free_all(headers);
          free(chunk.memory);
          curl_global_cleanup();
          return -1;
        }
        // Free JSON object
        json_object_put(parsed_json);
      }
    }

    // Clean up
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    if (chunk.memory)
      free(chunk.memory);
    curl_global_cleanup();

    return 0; // Success
  } else {
    debug("get_key_by_id: curl_easy_init() failed\n");
    curl_global_cleanup();
    return -1;
  }
}

// ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-

int kex_qkd128_etsi_014_keypair(struct kex *kex) {
  struct sshbuf *buf = NULL;
  size_t need;
  int r;

  QKD_Key key;
  int result = qkd_get_key(&key);

  if (result == 0) {
    // Print key_id and key in hex for testing purposes
    debug("Key ID: ");
    for (int i = 0; i < QKD_KEY_ID_LENGTH; i++) {
      debug("%02x", key.key_id[i]);
    }
    debug("\nKey Data: ");
    for (int i = 0; i < QKD_KEY_LENGTH; i++) {
      debug("%02x", key.key[i]);
    }
    debug("\n");
  } else {
    debug("Failed to retrieve key from QKD device\n");
  }

  self_report_usage();

  need = QKD_KEY_SIZE;
  memcpy(kex->qkd_client_key, key.key, need);
  memcpy(kex->qkd_key_id, key.key_id, QKD_KEY_ID_LENGTH);
  if ((buf = sshbuf_new()) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  need = QKD_KEY_ID_LENGTH;
  if ((r = sshbuf_reserve(buf, need, NULL)) != 0)
    goto out;
  sshbuf_reset(buf);
  if ((r = sshbuf_put(buf, key.key_id, need)) != 0)
    goto out;

  kex->client_pub = buf;
  buf = NULL;
out:
  sshbuf_free(buf);
  return r;
}

int kex_qkd128_etsi_014_enc(struct kex *kex, const struct sshbuf *client_blob,
                            struct sshbuf **server_blobp,
                            struct sshbuf **shared_secretp) {
  struct sshbuf *server_blob = NULL;
  struct sshbuf *buf = NULL;
  const u_char *key_id;
  u_char server_key[CURVE25519_SIZE];
  size_t need;
  int r;

  *server_blobp = NULL;
  *shared_secretp = NULL;

  need = QKD_KEY_ID_LENGTH;
  if (sshbuf_len(client_blob) != need) {
    r = SSH_ERR_SIGNATURE_INVALID;
    debug("%lu", sshbuf_len(client_blob));
    goto out;
  }
  key_id = sshbuf_ptr(client_blob);
  memcpy(kex->qkd_key_id, key_id, QKD_KEY_ID_LENGTH);

  debug("Key ID: ");
  for (int i = 0; i < QKD_KEY_ID_LENGTH; i++) {
    debug("%02x", key_id[i]);
  }
  QKD_Key key_by_id;
  if (qkd_get_key_by_id(key_id, &key_by_id) == 0) {
    // Print key data
    debug("Retrieved Key Data by ID: ");
    for (int i = 0; i < QKD_KEY_LENGTH; i++) {
      debug("%02x", key_by_id.key[i]);
    }
    debug("\n");
  } else {
    debug("Failed to retrieve key by ID from QKD device\n");
  }
  debug("\nKey Data: ");
  for (int i = 0; i < QKD_KEY_LENGTH; i++) {
    debug("%02x", key_by_id.key[i]);
  }

  need = QKD_KEY_SIZE;
  if ((server_blob = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  sshbuf_reset(server_blob);
  if ((r = sshbuf_reserve(server_blob, need, NULL)) != 0)
    goto out;
  if ((r = sshbuf_put(server_blob, key_by_id.key, need)) != 0)
    goto out;

  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(buf, need, NULL)) != 0)
    goto out;
  sshbuf_reset(buf);
  if ((r = sshbuf_put(buf, key_by_id.key, need)) != 0)
    goto out;

  *server_blobp = server_blob;
  *shared_secretp = buf;
  server_blob = NULL;
  buf = NULL;

out:
  sshbuf_free(server_blob);
  sshbuf_free(buf);
  return r;
}

int kex_qkd128_etsi_014_dec(struct kex *kex, const struct sshbuf *server_blob,
                            struct sshbuf **shared_secretp) {
  struct sshbuf *buf = NULL;
  const u_char *server_pub;
  u_char hash[SSH_DIGEST_MAX_LENGTH];
  size_t need;
  int r;

  *shared_secretp = NULL;

  need = QKD_KEY_SIZE;
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  if ((r = sshbuf_reserve(buf, need, NULL)) != 0)
    goto out;
  sshbuf_reset(buf);
  if ((r = sshbuf_put(buf, kex->qkd_client_key, QKD_KEY_SIZE)) != 0)
    goto out;

  *shared_secretp = buf;
  buf = NULL;
out:
  explicit_bzero(hash, sizeof(hash));
  sshbuf_free(buf);
  return r;
}
