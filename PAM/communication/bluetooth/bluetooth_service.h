#ifndef BLUETOOTH_SERVICE_H
#define BLUETOOTH_SERVICE_H

#include <stdbool.h>

/**
 * Start the Bluetooth service loop
 * Connects to the Bluetooth device and starts a polling thread
 */
void bluetooth_service_start();

/**
 * Stop the Bluetooth service loop
 * Stops the polling thread and disconnects from the device
 */
void bluetooth_service_stop();

/**
 * Check if the Bluetooth service is currently running
 *
 * @return true if service is running, false otherwise
 */
bool bluetooth_service_is_running();


bool bluetooth_service_is_connected();

#endif // BLUETOOTH_SERVICE_H

