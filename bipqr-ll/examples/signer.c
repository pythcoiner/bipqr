/* Smoke test for the C binding: read a signing request, answer with a PSBT.
 *
 * Build it against a staticlib crate that supplies the allocator and panic handler
 * and re-exports this crate's `ffi` module. See the README.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bipqr.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <request-file>\n", argv[0]);
        return 2;
    }

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("open");
        return 2;
    }
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (size < 0) {
        perror("seek");
        fclose(file);
        return 2;
    }
    rewind(file);
    uint8_t *blob = malloc(size > 0 ? (size_t)size : 1);
    if (blob == NULL) {
        perror("malloc");
        fclose(file);
        return 2;
    }
    size_t len = fread(blob, 1, (size_t)size, file);
    fclose(file);

    const bipqr_request *request = NULL;
    const char *err = NULL;
    int32_t code = bipqr_request_decode(blob, len, &request, &err);
    free(blob);
    if (code != BIPQR_OK) {
        fprintf(stderr, "decode failed (%d): %s\n", code, err);
        return 1;
    }
    if (request->message_type != BIPQR_MESSAGE_SIGNING) {
        fprintf(stderr, "not a signing request\n");
        bipqr_request_free(request);
        return 1;
    }

    const bipqr_sign *sign = &request->body.sign;
    printf("psbt: %zu bytes, %zu descriptor(s)\n", sign->psbt.len,
           sign->descriptors.len);
    for (size_t i = 0; i < sign->descriptors.len; i++) {
        printf("  descriptor %zu: %s\n", i, sign->descriptors.ptr[i].alias);
    }

    /* A real signer would sign here. This one echoes the PSBT back unchanged. */
    bipqr_response response;
    memcpy(response.id, request->id, BIPQR_REQUEST_ID_LEN);
    response.message_type = BIPQR_MESSAGE_SIGNING;
    response.is_error = false;
    response.body.signed_body.kind = BIPQR_SIGN_RESPONSE_PSBT;
    response.body.signed_body.value.psbt = sign->psbt;

    bipqr_buf out = {NULL, 0};
    code = bipqr_response_encode(&response, &out, &err);
    bipqr_request_free(request);
    if (code != BIPQR_OK) {
        fprintf(stderr, "encode failed (%d): %s\n", code, err);
        return 1;
    }
    printf("response: %zu bytes\n", out.len);
    bipqr_buf_free(out);
    return 0;
}
