#include "secure_ota_esp32.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "string.h"
#include "esp_idf_pre_encrypted_ota.h"


#define  APP_DESC_SIZE 256
#define  ENCRYPTED_APP_DESC_SIZE 512
#define  ENCRYPTED_SIGNATURE_SIZE 512
#define  RSA_SIGNATURE_LENGTH_BYTES 384
static const char *TAG = "secure_ota_esp32";

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

extern const char rsa_private_pem_start[] asm("_binary_private_manifest_pre_encryption_key_pem_start");
extern const char rsa_private_pem_end[]   asm("_binary_private_manifest_pre_encryption_key_pem_end");

extern const char rsa_public_manifest_key_pem_start[] asm("_binary_public_manifest_signing_key_pem_start");
extern const char rsa_public_manifest_key_pem_end[]   asm("_binary_public_manifest_signing_key_pem_end");


static const char *UPDATE_CHECK_URL = CONFIG_UPDATE_CHECK_URL;


void exit_sha256_digest(mbedtls_md_context_t *md_ctx) {
    mbedtls_md_free(md_ctx);
}

int create_sha256_digest(unsigned char *data, unsigned char *sha256_digest) {
    int ret = 0;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        ESP_LOGE(TAG, "Failed to initialize SHA256 md.");
        exit_sha256_digest(&md_ctx);
        return 1;
    }

    if ((ret = mbedtls_md_setup(&md_ctx, md_info, 0)) != 0) {
        ESP_LOGE(TAG, "Failed to initialize SHA256 context.");
        exit_sha256_digest(&md_ctx);
        return ret;
    }

    if ((ret = mbedtls_md(md_info, (const unsigned char *) data, APP_DESC_SIZE, (unsigned char *) sha256_digest)) != 0) {
        ESP_LOGE(TAG, "SHA256 computation failed.");
        exit_sha256_digest(&md_ctx);
        return ret;
    }

    return ret;
}

void exit_signature_verification(mbedtls_pk_context *pk_ctx, char *rsa_pem) {
    mbedtls_pk_free(pk_ctx);
    free(rsa_pem);
}

int verify_app_desc_signature(unsigned char *data, unsigned char *signature) {
    int ret = 0;

    mbedtls_pk_context pk;
    unsigned char sha256_digest[32];

    mbedtls_pk_init(&pk);

    int rsa_key_len = rsa_public_manifest_key_pem_end - rsa_public_manifest_key_pem_start;

    char *rsa_pem = calloc(1, rsa_key_len);
    if (!rsa_pem) {
        ESP_LOGE(TAG, "Couldn't allocate memory for rsa pem.");
    }

    memcpy(rsa_pem, rsa_public_manifest_key_pem_start, rsa_key_len);

    ESP_LOGI(TAG, "RSA public key import START!");
    if ((ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *) rsa_pem, rsa_key_len)) != 0) {
        ESP_LOGE(TAG, "RSA public key import FAILED.\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret);
        exit_signature_verification(&pk, rsa_pem);
        return ret;
    }
    ESP_LOGI(TAG, "RSA public key import SUCCESS!");

    ESP_LOGI(TAG, "SHA256 digest computation START!");
    if ((ret = create_sha256_digest(data, sha256_digest)) != 0) {
        ESP_LOGE(TAG, "App desc signature verification failed, SHA256 digest computation failure");
        exit_signature_verification(&pk, rsa_pem);
        return ret;
    }
    ESP_LOGI(TAG, "SHA256 digest computation SUCCESS!");

    ESP_LOGI(TAG, "Manifest signature verification START!");
    if ((ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, sha256_digest, 32, signature, RSA_SIGNATURE_LENGTH_BYTES)) != 0) {
        ESP_LOGE(TAG, "Manifest signature verification FAILED.\n  ! mbedtls_pk_verify returned -0x%04x\n", -ret);
        exit_signature_verification(&pk, rsa_pem);
        return ret;
    }
    ESP_LOGI(TAG, "Manifest signature verification SUCCESS!");

    exit_signature_verification(&pk, rsa_pem);
    return ret;

}


void exit_tls(mbedtls_pk_context *pk_ctx, mbedtls_entropy_context *entropy_ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx, char *rsa_pem) {
    free(rsa_pem);
    mbedtls_pk_free(pk_ctx);
    mbedtls_entropy_free(entropy_ctx);
    mbedtls_ctr_drbg_free(ctr_drbg_ctx);
}

int decrypt_data(unsigned char *input_buffer, int input_content_length, unsigned char *output_buffer, int output_content_length) {
    int ret = 0;

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_encrypt";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pk);

    int rsa_key_len = rsa_private_pem_end - rsa_private_pem_start;

    char *rsa_pem = calloc(1, rsa_key_len);
    if (!rsa_pem) {
        ESP_LOGE(TAG, "Couldn't allocate memory for rsa pem.");
    }
    memcpy(rsa_pem, rsa_private_pem_start, rsa_key_len);

    //Init entropy source
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
        ESP_LOGE(TAG, "failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret);
        exit_tls(&pk, &entropy, &ctr_drbg, rsa_pem);
        return ret;
    }

    ESP_LOGI(TAG, "Reading RSA private key START!");
    if ((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *) rsa_pem, rsa_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        ESP_LOGE(TAG, "Reading RSA private key FAILED!\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", (unsigned int) -ret);
        exit_tls(&pk, &entropy, &ctr_drbg, rsa_pem);
        return ret;
    }

    ESP_LOGI(TAG, "Reading RSA private key SUCCESS!");


    size_t result_size = 0;
    if ((ret = mbedtls_pk_decrypt(&pk, (const unsigned char *) input_buffer, input_content_length, output_buffer, &result_size, output_content_length, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        ESP_LOGE(TAG, "Decryption FAILED!\n  ! mbedtls_pk_decrypt returned -0x%04x\n", (unsigned int) -ret);
        exit_tls(&pk, &entropy, &ctr_drbg, rsa_pem);
        return ret;
    }

    if (output_content_length != result_size) {
        ESP_LOGI(TAG, "Decrypted content size mismatch. expected: %d, received: %d", output_content_length, result_size);
    }


    exit_tls(&pk, &entropy, &ctr_drbg, rsa_pem);
    return ret;
}


int decision_making(esp_app_desc_t *new_app_desc) {
    //feel free to add more info elements to app_desc_structure and extend the decision making process
    const esp_app_desc_t *current_app_desc = esp_ota_get_app_description();

    //dont update if secure version is lower than the current secure version
    if (new_app_desc->secure_version < current_app_desc->secure_version) {
        return 0;
    }

    //dont update, new app version is the same as current app version
    if (!strncmp(new_app_desc->version, current_app_desc->version, 32)) {
        return 0;
    }

    return 1;

}

void exit_check(char *http_buffer, esp_http_client_handle_t http_client) {
    free(http_buffer);
    esp_http_client_close(http_client);
    esp_http_client_cleanup(http_client);
}

int check_for_update(int *result) {
    *result = 0;
    int ret = 0;
    char *buffer = malloc(2048);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Cannot malloc http receive buffer");
        return 1;
    }
    //create configuration for http connection
    esp_http_client_config_t config = {
            .url = UPDATE_CHECK_URL,
            .port = 8443,
            .cert_pem = (char *) server_cert_pem_start,
            .skip_cert_common_name_check = true,
            .timeout_ms = 10000,
            .username = "fw_author",
            .password = "random_password",
            .auth_type = HTTP_AUTH_TYPE_BASIC,
    };

    esp_http_client_handle_t http_client = esp_http_client_init(&config);

    if (http_client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP connection");
        exit_check(buffer, http_client);
        return 2;
    }

    esp_err_t err;
    if ((err = esp_http_client_open(http_client, 0)) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        exit_check(buffer, http_client);
        return 3;
    }

    int content_length = esp_http_client_fetch_headers(http_client);
    ESP_LOGI(TAG, "content_length: %d", content_length);
    int total_read_len = 0, read_len;
    if (total_read_len < 512) {
        read_len = esp_http_client_read(http_client, buffer, 1024);
        if (read_len <= 0) {
            ESP_LOGE(TAG, "Error read data");
        }
        ESP_LOGI(TAG, "read_len = %d", read_len);
        total_read_len += read_len;
    }

    int status_code = esp_http_client_get_status_code(http_client);
    ESP_LOGI(TAG, "HTTP Stream reader Status = %d, content_length = %lld",
             status_code,
             esp_http_client_get_content_length(http_client));


    unsigned char app_desc_data_buffer[APP_DESC_SIZE];
    unsigned char signature_data_buffer[RSA_SIGNATURE_LENGTH_BYTES];

    ESP_LOGI(TAG, "Manifest data decryption START!");
    if ((ret = decrypt_data((unsigned char *) buffer, ENCRYPTED_APP_DESC_SIZE, app_desc_data_buffer, APP_DESC_SIZE)) != 0) {
        ESP_LOGE(TAG, "Manifest data decryption FAILED!");
        exit_check(buffer, http_client);
        return ret;
    }
    ESP_LOGI(TAG, "Manifest data decryption SUCCESS!");

    ESP_LOGI(TAG, "Manifest signature data decryption START!");
    if ((ret = decrypt_data((unsigned char *) &buffer[ENCRYPTED_APP_DESC_SIZE], ENCRYPTED_SIGNATURE_SIZE, signature_data_buffer, RSA_SIGNATURE_LENGTH_BYTES)) != 0) {
        ESP_LOGE(TAG, "Manifest signature data decryption FAILED!");
        exit_check(buffer, http_client);
        return ret;
    }
    ESP_LOGI(TAG, "Manifest signature data decryption SUCCESS!");

    //load app desc in the structure
    esp_app_desc_t *app_desc = (esp_app_desc_t *) app_desc_data_buffer;

    ESP_LOGI(TAG, "Manifest digital signature verification START!");
    if ((ret = verify_app_desc_signature((unsigned char *) app_desc_data_buffer, signature_data_buffer)) != 0) {
        ESP_LOGE(TAG, "Manifest digital signature verification FAILED!");
        exit_check(buffer, http_client);
        return ret;
    }
    ESP_LOGI(TAG, "Manifest digital signature verification SUCCESS!");

    ESP_LOGI(TAG, "App version info: \n"
                  "secure_version: %d\n"
                  "version: %-32s\n"
                  "project name: %-32s\n"
                  "compile date time: %-16s %-16s",
             app_desc->secure_version, app_desc->version, app_desc->project_name, app_desc->date, app_desc->time);

    exit_check(buffer, http_client);
    *result = decision_making(app_desc);
    return ret;
}

void perform_update() {
    xTaskCreate(&pre_encrypted_ota_task, "pre_encrypted_ota_task", 1024 * 8, NULL, 5, NULL);
}

