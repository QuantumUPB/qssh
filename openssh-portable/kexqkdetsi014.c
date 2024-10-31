#include "includes.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <time.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "log.h"

#define ENC_SAE_ID "UPB-BC-UPBR"
#define DEC_SAE_ID "UPB-BC-UPBP"

#define STATIC_CREDENTIALS
#define STATIC_ENC_IPPORT "141.85.241.65:12443"
#define STATIC_DEC_IPPORT "141.85.241.65:11443"

/* Define constants */
#define QKD_KEY_LENGTH 32
#define QKD_KEY_ID_LENGTH 16       // Assuming 128-bit key IDs

/* Define data structures */
typedef struct {
    uint8_t key_id[QKD_KEY_ID_LENGTH];
    uint8_t key[QKD_KEY_LENGTH];
} QKD_Key;

// ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-

#define ENC_SAE_ID "UPB-BC-UPBR"
#define DEC_SAE_ID "UPB-BC-UPBP"

#define STATIC_CREDENTIALS
#define STATIC_ENC_IPPORT "141.85.241.65:12443"
#define STATIC_DEC_IPPORT "141.85.241.65:11443"

static int Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    // Base64 decoding table
    static const unsigned char decoding_table[256] = {
        [0 ... 255] = 0x80, // Initialize all elements to invalid marker (0x80)
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,
        ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
        ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
        ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
        ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25,
        ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
        ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
        ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
        ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
        ['y'] = 50, ['z'] = 51,
        ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
        ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61,
        ['+'] = 62, ['/'] = 63
    };
    
    size_t input_length = strlen(b64message);
    size_t padding = 0;
    
    // Check for padding characters and adjust input length accordingly
    if (input_length >= 2) {
        if (b64message[input_length - 1] == '=' && b64message[input_length - 2] == '=') {
            padding = 2;
        }
        else if (b64message[input_length - 1] == '=') {
            padding = 1;
        }
    }
    
    // Calculate the expected length of the decoded data
    *length = (input_length * 3) / 4 - padding;
    
    // Allocate memory for the decoded data
    *buffer = (unsigned char*)malloc(*length);
    if (*buffer == NULL) {
        return -1; // Memory allocation failure
    }
    
    size_t i = 0, j = 0;
    unsigned int sextet_a, sextet_b, sextet_c, sextet_d;
    
    while (i < input_length) {
        // Read four base64 characters
        sextet_a = b64message[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)b64message[i++]];
        sextet_b = b64message[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)b64message[i++]];
        sextet_c = b64message[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)b64message[i++]];
        sextet_d = b64message[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)b64message[i++]];
        
        // Validate characters
        if (sextet_a == 0x80 || sextet_b == 0x80 ||
            (sextet_c == 0x80 && b64message[i - 2] != '=') ||
            (sextet_d == 0x80 && b64message[i - 1] != '=')) {
            free(*buffer);
            *buffer = NULL;
            return -1; // Invalid character detected
        }
        
        // Combine the sextets into bytes
        unsigned int triple = (sextet_a << 18) + (sextet_b << 12) + 
                               (sextet_c << 6) + sextet_d;
        
        if (j < *length) (*buffer)[j++] = (triple >> 16) & 0xFF;
        if (j < *length) (*buffer)[j++] = (triple >> 8) & 0xFF;
        if (j < *length) (*buffer)[j++] = triple & 0xFF;
    }
    
    return 0; // Success
}

static int hex_char_to_value(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    }
    else if ('a' <= c && c <= 'f') {
        return 10 + (c - 'a');
    }
    else if ('A' <= c && c <= 'F') {
        return 10 + (c - 'A');
    }
    else {
        return -1;
    }
}

/* 
 * Checks if a character is a valid hexadecimal digit or a hyphen.
 */
static int is_valid_uuid_char(char c) {
    return (('0' <= c && c <= '9') ||
            ('a' <= c && c <= 'f') ||
            ('A' <= c && c <= 'F') ||
            (c == '-'));
}

/* 
 * Converts a UUID string to a 16-byte array.
 * 
 * Parameters:
 *   - uuid_str: The null-terminated UUID string.
 *   - uuid_bytes: A 16-byte array to store the resulting binary UUID.
 * 
 * Returns:
 *   - 0 on success.
 *   - -1 on failure (invalid format).
 */
static int UUIDStringToBytes(const char* uuid_str, uint8_t* uuid_bytes) {
    if (uuid_str == NULL || uuid_bytes == NULL) {
        return -1;
    }

    // Expected UUID format length
    const int UUID_STR_LEN = 36;

    // Check the length of the UUID string
    if (strlen(uuid_str) != UUID_STR_LEN) {
        return -1;
    }

    // Hyphen positions in a UUID string
    const int hyphen_positions[] = {8, 13, 18, 23};
    int hyphen_count = sizeof(hyphen_positions) / sizeof(hyphen_positions[0]);

    // Validate hyphens at correct positions
    for (int i = 0; i < hyphen_count; i++) {
        if (uuid_str[hyphen_positions[i]] != '-') {
            return -1;
        }
    }

    // Validate all other characters
    for (int i = 0; i < UUID_STR_LEN; i++) {
        // Skip hyphens
        int is_hyphen = 0;
        for (int j = 0; j < hyphen_count; j++) {
            if (i == hyphen_positions[j]) {
                is_hyphen = 1;
                break;
            }
        }
        if (is_hyphen) {
            continue;
        }
        if (!is_valid_uuid_char(uuid_str[i])) {
            return -1;
        }
    }

    // Convert UUID string to bytes
    int byte_index = 0;
    for (int i = 0; i < UUID_STR_LEN; i++) {
        // Skip hyphens
        int is_hyphen = 0;
        for (int j = 0; j < hyphen_count; j++) {
            if (i == hyphen_positions[j]) {
                is_hyphen = 1;
                break;
            }
        }
        if (is_hyphen) {
            continue;
        }

        // Convert two hex characters to one byte
        if (i + 1 >= UUID_STR_LEN) {
            // Unexpected end
            return -1;
        }

        int high = hex_char_to_value(uuid_str[i]);
        int low = hex_char_to_value(uuid_str[i + 1]);

        if (high == -1 || low == -1) {
            return -1;
        }

        uuid_bytes[byte_index++] = (high << 4) | low;
        i++; // Skip the next character as it's already processed
    }

    // Final byte index should be 16
    if (byte_index != 16) {
        return -1;
    }

    return 0; // Success
}

/* 
 * Converts a 16-byte UUID array to a UUID string.
 * 
 * Parameters:
 *   - uuid_bytes: A 16-byte array containing the binary UUID.
 *   - uuid_str: A 37-byte buffer to store the resulting UUID string (36 characters + null terminator).
 * 
 * Note:
 *   - The uuid_str buffer must be at least 37 bytes long.
 */
static void UUIDBytesToString(const uint8_t* uuid_bytes, char* uuid_str) {
    if (uuid_bytes == NULL || uuid_str == NULL) {
        return;
    }

    // Positions where hyphens should be inserted
    const int hyphen_positions[] = {8, 13, 18, 23};
    int hyphen_count = sizeof(hyphen_positions) / sizeof(hyphen_positions[0]);
    int hyphen_index = 0;

    int str_index = 0;
    for (int i = 0; i < 16; i++) {
        // Insert hyphen if needed
        if (hyphen_index < hyphen_count && str_index == hyphen_positions[hyphen_index]) {
            uuid_str[str_index++] = '-';
            hyphen_index++;
        }

        // Convert byte to two hex characters
        unsigned char byte = uuid_bytes[i];
        uuid_str[str_index++] = "0123456789abcdef"[byte >> 4];
        uuid_str[str_index++] = "0123456789abcdef"[byte & 0x0F];
    }

    uuid_str[str_index] = '\0'; // Null-terminate the string
}

int qkd_get_key(QKD_Key *key) {
     if (key == NULL) {
        return -1;
    }

    memset(key, 0, sizeof(QKD_Key));

    int pipefd[2];
    pid_t pid;
    int status;
    ssize_t bytes_read;
    char *output = NULL;
    size_t output_size = 0;
    size_t buffer_size = 4096; // Initial buffer size

    // Initialize memory for capturing output
    output = malloc(buffer_size);
    if (output == NULL) {
        debug("get_key_from_qkd: Failed to allocate memory\n");
        return -1;
    }

    // Create a pipe
    if (pipe(pipefd) == -1) {
        debug("get_key_from_qkd: pipe() failed: %s\n", strerror(errno));
        free(output);
        return -1;
    }

    // Fork the process
    pid = fork();
    if (pid == -1) {
        debug("get_key_from_qkd: fork() failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        free(output);
        return -1;
    }

    if (pid == 0) {
        // Child process
        // Redirect stdout to the pipe's write end
        close(pipefd[0]); // Close unused read end
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            debug("get_key_from_qkd_ (child): dup2() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        // Redirect stderr to the pipe's write end (optional)
        if (dup2(pipefd[1], STDERR_FILENO) == -1) {
            debug("get_key_from_qkd_ (child): dup2() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        close(pipefd[1]); // Close the original write end after duplicating

        // Construct the curl command arguments
#ifdef STATIC_CREDENTIALS
        const char *qkd_ipport_value = STATIC_ENC_IPPORT;
#else
        // Get QKD IP and port from environment variable
        const char *env_qkd_ipport_name = "QKD_IPPORT";
        char *qkd_ipport_value = getenv(env_qkd_ipport_name);
        if (qkd_ipport_value == NULL) {
            debug("Environment variable %s is not set.\n", env_qkd_ipport_name);
            exit(EXIT_FAILURE);
        }
#endif

        // Build the URL
        char qkd_url[256];
        snprintf(qkd_url, sizeof(qkd_url), "https://%s/api/v1/keys/" ENC_SAE_ID "/enc_keys", qkd_ipport_value);

        // Build the curl command arguments
#ifdef STATIC_CREDENTIALS
        const char *ssl_cert = "/certs/qkd.crt";
        const char *ssl_key = "/certs/qkd.key";
        const char *cacert = "/certs/qkd-ca.crt";
#else
        const char *env_ssl_cert_name = "QKD_SSL_CERT";
        char *env_ssl_cert_value = getenv(env_ssl_cert_name);
        if (env_ssl_cert_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ssl_cert_name);
            exit(EXIT_FAILURE);
        }

        const char *env_ssl_key_name = "QKD_SSL_KEY"; // Corrected variable name
        char *env_ssl_key_value = getenv(env_ssl_key_name);
        if (env_ssl_key_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ssl_key_name);
            exit(EXIT_FAILURE);
        }

        const char *env_ca_name = "QKD_CA_CERT"; // Corrected variable name
        char *env_ca_value = getenv(env_ca_name);
        if (env_ca_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ca_name);
            exit(EXIT_FAILURE);
        }
#endif

        // Construct the exec arguments
#ifdef STATIC_CREDENTIALS
        execlp("curl", "curl",
               "-s", // Silent mode
               "-k", // Insecure, skip SSL verification
               "--cert", ssl_cert,
               "--key", ssl_key,
               "--cacert", cacert,
               "-X", "GET",
               qkd_url,
               NULL);
#else
        execlp("curl", "curl",
               "-s", // Silent mode
               "-k", // Insecure, skip SSL verification
               "--cert", env_ssl_cert_value,
               "--key", env_ssl_key_value,
               "--cacert", env_ca_value,
               "-X", "GET",
               qkd_url,
               NULL);
#endif

        // If execlp returns, it failed
        debug("Failed to execute curl: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        close(pipefd[1]); // Close unused write end

        // Read from the pipe
        while ((bytes_read = read(pipefd[0], output + output_size, buffer_size - output_size - 1)) > 0) {
            output_size += bytes_read;
            // Reallocate buffer if needed
            if (output_size >= buffer_size - 1) {
                buffer_size *= 2;
                char *temp = realloc(output, buffer_size);
                if (temp == NULL) {
                    debug("get_key_from_qkd: realloc() failed\n");
                    close(pipefd[0]);
                    free(output);
                    return -1;
                }
                output = temp;
            }
        }

        if (bytes_read == -1) {
            debug("get_key_from_qkd: read() failed: %s\n", strerror(errno));
            close(pipefd[0]);
            free(output);
            return -1;
        }

        // Null-terminate the output
        output[output_size] = '\0';

        close(pipefd[0]);

        // Wait for the child process to finish
        if (waitpid(pid, &status, 0) == -1) {
            debug("get_key_from_qkd: waitpid() failed: %s\n", strerror(errno));
            free(output);
            return -1;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            debug("get_key_from_qkd: curl command failed with status %d\n", WEXITSTATUS(status));
            debug("Curl output: %s\n", output);
            free(output);
            return -1;
        }

        // Parse the JSON response
        struct json_object *parsed_json = json_tokener_parse(output);
        if (parsed_json == NULL) {
            debug("get_key_from_qkd: Failed to parse JSON response\n");
            free(output);
            return -1;
        }

        struct json_object *keys_array;
        struct json_object *key_obj;
        struct json_object *key_str_obj;
        struct json_object *key_id_obj;

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
                        if (key_data_len != sizeof(key->key)) { // Assuming QKD_KEY_LENGTH is 32
                            debug("get_key_from_qkd: Invalid key length after Base64 decoding\n");
                            free(key_data);
                            json_object_put(parsed_json);
                            free(output);
                            return -1;
                        } else {
                            memcpy(key->key, key_data, sizeof(key->key));
                            free(key_data);
                        }
                    } else {
                        debug("get_key_from_qkd: Failed to decode Base64 key\n");
                        json_object_put(parsed_json);
                        free(output);
                        return -1;
                    }

                    // Convert UUID string to bytes
                    if (UUIDStringToBytes(key_id_str, key->key_id) != 0) {
                        debug("get_key_from_qkd: Failed to convert key_ID to bytes\n");
                        json_object_put(parsed_json);
                        free(output);
                        return -1;
                    }
                } else {
                    debug("get_key_from_qkd: JSON key object does not contain expected fields\n");
                    json_object_put(parsed_json);
                    free(output);
                    return -1;
                }
            } else {
                debug("get_key_from_qkd: No keys available in response\n");
                json_object_put(parsed_json);
                free(output);
                return -1;
            }
        } else {
            debug("get_key_from_qkd: JSON response does not contain 'keys' array\n");
            json_object_put(parsed_json);
            free(output);
            return -1;
        }

        // Free JSON object and output buffer
        json_object_put(parsed_json);
        free(output);

        return 0; // Success
    }
}

int qkd_get_key_by_id(const uint8_t key_id[QKD_KEY_ID_LENGTH], QKD_Key *key) {
    if (key_id == NULL || key == NULL) {
        return -1;
    }

    memset(key, 0, sizeof(QKD_Key));

    int pipefd[2];
    pid_t pid;
    int status;
    ssize_t bytes_read;
    size_t buffer_size = 4096; // Initial buffer size
    size_t output_size = 0;
    char *output = NULL;

    // Allocate initial memory for output
    output = malloc(buffer_size);
    if (output == NULL) {
        debug("qkd_get_key_by_id: Failed to allocate memory\n");
        return -1;
    }
    // Create a pipe
    if (pipe(pipefd) == -1) {
        debug("qkd_get_key_by_id: pipe() failed: %s\n", strerror(errno));
        free(output);
        return -1;
    }

    // Fork the process
    pid = fork();
    if (pid == -1) {
        debug("qkd_get_key_by_id: fork() failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        free(output);
        return -1;
    }

    if (pid == 0) {
        // Child process
        // Redirect stdout to pipe's write end
        close(pipefd[0]); // Close unused read end
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            debug("qkd_get_key_by_id_ (child): dup2() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        // Redirect stderr to pipe's write end (optional)
        if (dup2(pipefd[1], STDERR_FILENO) == -1) {
            debug("qkd_get_key_by_id_ (child): dup2() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        close(pipefd[1]); // Close original write end after duplicating

        // Determine QKD IP and port
#ifdef STATIC_CREDENTIALS
        const char *qkd_ipport_value = STATIC_DEC_IPPORT;
#else
        // Get QKD IP and port from environment variable
        const char *env_qkd_ipport_name = "QKD_IPPORT";
        char *qkd_ipport_value = getenv(env_qkd_ipport_name);
        if (qkd_ipport_value == NULL) {
            debug("Environment variable %s is not set.\n", env_qkd_ipport_name);
            exit(EXIT_FAILURE);
        }
#endif

        // Build the URL
        char qkd_url[256];
        snprintf(qkd_url, sizeof(qkd_url), "https://%s/api/v1/keys/%s/dec_keys", qkd_ipport_value, DEC_SAE_ID);

        // Build the JSON payload
        // Convert key_id (binary) to UUID string
        char key_id_str[37]; // UUID string is 36 characters + null terminator
        UUIDBytesToString(key_id, key_id_str);

        // Prepare JSON data
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "{ \"key_IDs\":[{ \"key_ID\": \"%s\" }] }", key_id_str);

        // Determine SSL certificate paths
#ifdef STATIC_CREDENTIALS
        const char *ssl_cert = "/certs/qkd.crt";
        const char *ssl_key = "/certs/qkd-new.key";
        const char *cacert = "/certs/qkd-ca.crt";
#else
        // Get SSL cert paths from environment variables
        const char *env_ssl_cert_name = "QKD_SSL_CERT";
        char *env_ssl_cert_value = getenv(env_ssl_cert_name);
        if (env_ssl_cert_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ssl_cert_name);
            exit(EXIT_FAILURE);
        }

        const char *env_ssl_key_name = "QKD_SSL_KEY"; // Corrected variable name
        char *env_ssl_key_value = getenv(env_ssl_key_name);
        if (env_ssl_key_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ssl_key_name);
            exit(EXIT_FAILURE);
        }

        const char *env_ca_name = "QKD_CA_CERT"; // Corrected variable name
        char *env_ca_value = getenv(env_ca_name);
        if (env_ca_value == NULL) {
            debug("Environment variable %s is not set.\n", env_ca_name);
            exit(EXIT_FAILURE);
        }
#endif

        // Construct the curl command
#ifdef STATIC_CREDENTIALS
        execlp("curl", "curl",
               "-s",              // Silent mode
               "-k",              // Insecure, skip SSL verification
               "--cert", ssl_cert,
               "--key", ssl_key,
               "--cacert", cacert,
               "-X", "POST",
               "-H", "Content-Type: application/json",
               "-d", post_data,
               qkd_url,
               NULL);
#else
        execlp("curl", "curl",
               "-s",              // Silent mode
               "-k",              // Insecure, skip SSL verification
               "--cert", env_ssl_cert_value,
               "--key", env_ssl_key_value,
               "--cacert", env_ca_value,
               "-X", "POST",
               "-H", "Content-Type: application/json",
               "-d", post_data,
               qkd_url,
               NULL);
#endif

        // If execlp returns, it failed
        debug("qkd_get_key_by_id: Failed to execute curl: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        close(pipefd[1]); // Close unused write end

        // Initialize output buffer
        output = malloc(buffer_size);
        if (output == NULL) {
            debug("qkd_get_key_by_id: Failed to allocate memory for output\n");
            close(pipefd[0]);
            return -1;
        }
        memset(output, 0, buffer_size);

        // Read from the pipe
        while ((bytes_read = read(pipefd[0], output + output_size, buffer_size - output_size - 1)) > 0) {
            output_size += bytes_read;
            // Reallocate buffer if needed
            if (output_size >= buffer_size - 1) {
                buffer_size *= 2;
                char *temp = realloc(output, buffer_size);
                if (temp == NULL) {
                    debug("qkd_get_key_by_id: realloc() failed\n");
                    free(output);
                    close(pipefd[0]);
                    return -1;
                }
                output = temp;
            }
        }

        if (bytes_read == -1) {
            debug("qkd_get_key_by_id: read() failed: %s\n", strerror(errno));
            free(output);
            close(pipefd[0]);
            return -1;
        }

        // Null-terminate the output
        output[output_size] = '\0';
        close(pipefd[0]);

        // Wait for the child process to finish
        if (waitpid(pid, &status, 0) == -1) {
            debug("qkd_get_key_by_id: waitpid() failed: %s\n", strerror(errno));
            free(output);
            return -1;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            debug("qkd_get_key_by_id: curl command failed with status %d\n", WEXITSTATUS(status));
            debug("Curl output: %s\n", output);
            free(output);
            return -1;
        }

        if (output_size == 0) {
            debug("qkd_get_key_by_id: No output received from curl command\n");
            free(output);
            return -1;
        }

        // Parse the JSON response
        struct json_object *parsed_json = json_tokener_parse(output);
        free(output);
        if (parsed_json == NULL) {
            debug("qkd_get_key_by_id: Failed to parse JSON response\n");
            return -1;
        }

        struct json_object *keys_array;
        struct json_object *key_obj;
        struct json_object *key_str_obj;
        struct json_object *key_id_obj;

        if (json_object_object_get_ex(parsed_json, "keys", &keys_array)) {
            size_t n_keys = json_object_array_length(keys_array);
            if (n_keys > 0) {
                key_obj = json_object_array_get_idx(keys_array, 0);
                if (json_object_object_get_ex(key_obj, "key", &key_str_obj) &&
                    json_object_object_get_ex(key_obj, "key_ID", &key_id_obj)) {

                    const char *key_b64_str = json_object_get_string(key_str_obj);
                    const char *key_id_response_str = json_object_get_string(key_id_obj);

                    if (key_b64_str == NULL || key_id_response_str == NULL) {
                        debug("qkd_get_key_by_id: 'key' or 'key_ID' field is missing in JSON response\n");
                        json_object_put(parsed_json);
                        return -1;
                    }

                    // Base64 decode the key
                    unsigned char *key_data = NULL;
                    size_t key_data_len = 0;
                    if (Base64Decode(key_b64_str, &key_data, &key_data_len) != 0) {
                        debug("qkd_get_key_by_id: Failed to decode Base64 key\n");
                        json_object_put(parsed_json);
                        return -1;
                    }

                    if (key_data_len != QKD_KEY_LENGTH) {
                        debug("qkd_get_key_by_id: Invalid key length after Base64 decoding\n");
                        free(key_data);
                        json_object_put(parsed_json);
                        return -1;
                    }

                    memcpy(key->key, key_data, QKD_KEY_LENGTH);
                    free(key_data);

                    // Convert UUID string to bytes
                    if (UUIDStringToBytes(key_id_response_str, key->key_id) != 0) {
                        debug("qkd_get_key_by_id: Failed to convert key_ID to bytes\n");
                        json_object_put(parsed_json);
                        return -1;
                    }

                    // Verify that the returned key_id matches the requested key_id
                    if (memcmp(key->key_id, key_id, QKD_KEY_ID_LENGTH) != 0) {
                        debug("qkd_get_key_by_id: Response key_ID does not match requested key_ID\n");
                        json_object_put(parsed_json);
                        return -1;
                    }

                } else {
                    debug("qkd_get_key_by_id: JSON key object does not contain expected fields\n");
                    json_object_put(parsed_json);
                    return -1;
                }
            } else {
                debug("qkd_get_key_by_id: No keys available in response\n");
                json_object_put(parsed_json);
                return -1;
            }
        } else {
            debug("qkd_get_key_by_id: JSON response does not contain 'keys' array\n");
            json_object_put(parsed_json);
            return -1;
        }

        // Free JSON object
        json_object_put(parsed_json);

        free(output);
        return 0; // Success
    }
}



// ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-

int kex_qkd128_etsi_014_keypair(struct kex *kex) {
	struct sshbuf *buf = NULL;
	size_t need;
	int r;

    uint8_t actual_key[QKD_KEY_SIZE] = "abcdefghabcdefghabcdefghabcdefgh";
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

	need = QKD_KEY_SIZE;
    memcpy(kex->qkd_client_key, actual_key, need);
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
	struct sshbuf **server_blobp, struct sshbuf **shared_secretp) {
    struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *key_id;
	u_char server_key[CURVE25519_SIZE];
	size_t need;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

    uint8_t actual_key[QKD_KEY_SIZE] = "abcdefghabcdefghabcdefghabcdefgh";

	need = QKD_KEY_ID_LENGTH;
	if (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
        debug("%lu", sshbuf_len(client_blob));
		goto out;
	}
	key_id = sshbuf_ptr(client_blob);
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
    // Replace this with the qkd key.
    if ((r = sshbuf_put(server_blob, actual_key,
	    need)) != 0)
		goto out;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
    if ((r = sshbuf_reserve(buf, need, NULL)) != 0)
		goto out; 
    sshbuf_reset(buf);
	if ((r = sshbuf_put(buf, actual_key,
	    need)) != 0)
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
	if ((r = sshbuf_put(buf, kex->qkd_client_key,
	    CURVE25519_SIZE)) != 0)
		goto out;

	*shared_secretp = buf;
	buf = NULL;
out:
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(buf);
	return r;
}