#ifndef SDP_MANAGER_H
#define SDP_MANAGER_H

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

sdp_session_t *create_sdp_session(const char *mac);
sdp_list_t *get_sdp_response_with_uuid(sdp_session_t *session, const char *uuid_string);
void extract_RFCOMM_channel(int *channel, sdp_list_t *response_list);
void free_sdp_response(sdp_list_t *response_list);
#endif // SDP_MANAGER_H
