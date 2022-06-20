#pragma once
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Checks if any update is available on the update server.
 * @returns 0 is checkup was successful @else Value > 0 if checkup failed.
 * @param result Output parameter that is set to 1 if update is available, else is set to 0;
 * @warning Update server check url has to be configured.
 * */
int check_for_update(int * result);

/**
 * Updates the device to the newest update available on update server in accordance with the ESP-IDF Pre-Encrypted HTTPS OTA solution.
 * @note Update server url has to be configured.
 * */
void perform_update();

#ifdef __cplusplus
}
#endif