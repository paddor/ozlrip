// Thin C layer over OpenZL for ozlrip benchmarks and interop tests.
//
// Every function returns 0 on success or a nonzero OpenZL error code. The
// message for the last failure on this thread is available from
// ozlrip_shim_last_error().

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "openzl/openzl.h"

static _Thread_local char OZLRIP_SHIM_LAST_ERROR[8192];

static int set_error_message(const char* message)
{
    snprintf(
            OZLRIP_SHIM_LAST_ERROR,
            sizeof(OZLRIP_SHIM_LAST_ERROR),
            "%s",
            message);
    return -1;
}

static int set_dctx_error(ZL_DCtx* dctx, const char* message, ZL_Report report)
{
    int const code         = (int)ZL_errorCode(report);
    const char* const name = ZL_ErrorCode_toString((ZL_ErrorCode)code);
    const char* const context = ZL_DCtx_getErrorContextString(dctx, report);
    snprintf(
            OZLRIP_SHIM_LAST_ERROR,
            sizeof(OZLRIP_SHIM_LAST_ERROR),
            "%s: code=%d %s; context=%s",
            message,
            code,
            name ? name : "<null>",
            context ? context : "<null>");
    return code;
}

static int set_cctx_error(ZL_CCtx* cctx, const char* message, ZL_Report report)
{
    int const code         = (int)ZL_errorCode(report);
    const char* const name = ZL_ErrorCode_toString((ZL_ErrorCode)code);
    const char* const context = ZL_CCtx_getErrorContextString(cctx, report);
    snprintf(
            OZLRIP_SHIM_LAST_ERROR,
            sizeof(OZLRIP_SHIM_LAST_ERROR),
            "%s: code=%d %s; context=%s",
            message,
            code,
            name ? name : "<null>",
            context ? context : "<null>");
    return code;
}

const char* ozlrip_shim_last_error(void)
{
    return OZLRIP_SHIM_LAST_ERROR;
}

unsigned ozlrip_shim_min_format_version(void)
{
    return ZL_MIN_FORMAT_VERSION;
}

unsigned ozlrip_shim_max_format_version(void)
{
    return ZL_MAX_FORMAT_VERSION;
}

unsigned ozlrip_shim_default_format_version(void)
{
    return ZL_getDefaultEncodingVersion();
}

// ---------------------------------------------------------------------------
// Decompression
// ---------------------------------------------------------------------------

ZL_DCtx* ozlrip_shim_dctx_create(void)
{
    return ZL_DCtx_create();
}

void ozlrip_shim_dctx_free(ZL_DCtx* dctx)
{
    ZL_DCtx_free(dctx);
}

int ozlrip_shim_dctx_disable_checksums(ZL_DCtx* dctx)
{
    ZL_Report report =
            ZL_DCtx_setParameter(dctx, ZL_DParam_stickyParameters, 1);
    if (ZL_isError(report)) {
        return set_dctx_error(dctx, "ZL_DCtx_setParameter(sticky)", report);
    }
    report = ZL_DCtx_setParameter(
            dctx, ZL_DParam_checkCompressedChecksum, ZL_TernaryParam_disable);
    if (ZL_isError(report)) {
        return set_dctx_error(
                dctx, "ZL_DCtx_setParameter(compressed checksum)", report);
    }
    report = ZL_DCtx_setParameter(
            dctx, ZL_DParam_checkContentChecksum, ZL_TernaryParam_disable);
    if (ZL_isError(report)) {
        return set_dctx_error(
                dctx, "ZL_DCtx_setParameter(content checksum)", report);
    }
    return 0;
}

int ozlrip_shim_decompress_serial(
        ZL_DCtx* dctx,
        void* dst,
        size_t dst_capacity,
        const void* src,
        size_t src_size,
        size_t* written)
{
    ZL_TypedBuffer* const output =
            ZL_TypedBuffer_createWrapSerial(dst, dst_capacity);
    if (output == NULL) {
        return set_error_message(
                "ZL_TypedBuffer_createWrapSerial returned NULL");
    }
    ZL_Report const report =
            ZL_DCtx_decompressTBuffer(dctx, output, src, src_size);
    ZL_TypedBuffer_free(output);
    if (ZL_isError(report)) {
        return set_dctx_error(dctx, "ZL_DCtx_decompressTBuffer", report);
    }
    *written = ZL_validResult(report);
    return 0;
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

// Keep in sync with `Graph` in src/lib.rs.
enum {
    OZLRIP_SHIM_GRAPH_GENERIC  = 0,
    OZLRIP_SHIM_GRAPH_STORE    = 1,
    OZLRIP_SHIM_GRAPH_ZSTD     = 2,
    OZLRIP_SHIM_GRAPH_LZ4      = 3,
    OZLRIP_SHIM_GRAPH_FSE      = 4,
    OZLRIP_SHIM_GRAPH_HUFFMAN  = 5,
    OZLRIP_SHIM_GRAPH_ENTROPY  = 6,
    OZLRIP_SHIM_GRAPH_FIELD_LZ = 7,
    OZLRIP_SHIM_GRAPH_BITPACK  = 8,
    OZLRIP_SHIM_GRAPH_FLATPACK = 9,
    OZLRIP_SHIM_GRAPH_CONSTANT = 10,
    OZLRIP_SHIM_GRAPH_NUMERIC  = 11,
};

static int graph_id(int graph, ZL_GraphID* out)
{
    switch (graph) {
        case OZLRIP_SHIM_GRAPH_GENERIC:
            *out = ZL_GRAPH_COMPRESS_GENERIC;
            return 0;
        case OZLRIP_SHIM_GRAPH_STORE:
            *out = ZL_GRAPH_STORE;
            return 0;
        case OZLRIP_SHIM_GRAPH_ZSTD:
            *out = ZL_GRAPH_ZSTD;
            return 0;
        case OZLRIP_SHIM_GRAPH_LZ4:
            *out = ZL_GRAPH_LZ4;
            return 0;
        case OZLRIP_SHIM_GRAPH_FSE:
            *out = ZL_GRAPH_FSE;
            return 0;
        case OZLRIP_SHIM_GRAPH_HUFFMAN:
            *out = ZL_GRAPH_HUFFMAN;
            return 0;
        case OZLRIP_SHIM_GRAPH_ENTROPY:
            *out = ZL_GRAPH_ENTROPY;
            return 0;
        case OZLRIP_SHIM_GRAPH_FIELD_LZ:
            *out = ZL_GRAPH_FIELD_LZ;
            return 0;
        case OZLRIP_SHIM_GRAPH_BITPACK:
            *out = ZL_GRAPH_BITPACK;
            return 0;
        case OZLRIP_SHIM_GRAPH_FLATPACK:
            *out = ZL_GRAPH_FLATPACK;
            return 0;
        case OZLRIP_SHIM_GRAPH_CONSTANT:
            *out = ZL_GRAPH_CONSTANT;
            return 0;
        case OZLRIP_SHIM_GRAPH_NUMERIC:
            *out = ZL_GRAPH_NUMERIC;
            return 0;
        default:
            return set_error_message("unknown ozlrip shim graph");
    }
}

// Keep in sync with `InputKind` in src/lib.rs.
enum {
    OZLRIP_SHIM_INPUT_SERIAL  = 0,
    OZLRIP_SHIM_INPUT_STRUCT  = 1,
    OZLRIP_SHIM_INPUT_NUMERIC = 2,
    OZLRIP_SHIM_INPUT_STRING  = 3,
};

typedef struct {
    int kind;
    const void* data;
    size_t data_size;
    size_t width;
    const uint32_t* lengths;
    size_t count;
} ozlrip_shim_input;

static ZL_TypedRef* typed_ref(const ozlrip_shim_input* input)
{
    switch (input->kind) {
        case OZLRIP_SHIM_INPUT_SERIAL:
            return ZL_TypedRef_createSerial(input->data, input->data_size);
        case OZLRIP_SHIM_INPUT_STRUCT:
            return ZL_TypedRef_createStruct(
                    input->data, input->width, input->count);
        case OZLRIP_SHIM_INPUT_NUMERIC:
            return ZL_TypedRef_createNumeric(
                    input->data, input->width, input->count);
        case OZLRIP_SHIM_INPUT_STRING:
            return ZL_TypedRef_createString(
                    input->data,
                    input->data_size,
                    input->lengths,
                    input->count);
        default:
            return NULL;
    }
}

// Compresses `nb_inputs` typed inputs with one standard starting graph.
// `format_version` 0 selects the library default.
int ozlrip_shim_compress(
        int graph,
        unsigned format_version,
        int compression_level,
        const ozlrip_shim_input* inputs,
        size_t nb_inputs,
        void* dst,
        size_t dst_capacity,
        size_t* written)
{
    enum { MAX_INPUTS = 64 };
    if (nb_inputs == 0 || nb_inputs > MAX_INPUTS) {
        return set_error_message("input count must be between 1 and 64");
    }
    ZL_GraphID start;
    if (graph_id(graph, &start) != 0) {
        return -1;
    }

    int result                  = -1;
    ZL_Compressor* compressor   = ZL_Compressor_create();
    ZL_CCtx* cctx               = ZL_CCtx_create();
    const ZL_TypedRef* refs[MAX_INPUTS];
    size_t nb_refs = 0;
    if (compressor == NULL || cctx == NULL) {
        set_error_message("OpenZL context allocation failed");
        goto cleanup;
    }

    // The library rejects an unset (0) format version at compression time,
    // although its header documents 0 as "use the default".
    if (format_version == 0) {
        format_version = ZL_getDefaultEncodingVersion();
    }
    ZL_Report report = ZL_Compressor_setParameter(
            compressor, ZL_CParam_formatVersion, (int)format_version);
    if (ZL_isError(report)) {
        set_error_message("ZL_Compressor_setParameter(formatVersion) failed");
        goto cleanup;
    }
    report = ZL_Compressor_setParameter(
            compressor, ZL_CParam_compressionLevel, compression_level);
    if (ZL_isError(report)) {
        set_error_message("ZL_Compressor_setParameter(level) failed");
        goto cleanup;
    }
    report = ZL_Compressor_selectStartingGraphID(compressor, start);
    if (ZL_isError(report)) {
        set_error_message("ZL_Compressor_selectStartingGraphID failed");
        goto cleanup;
    }
    report = ZL_CCtx_refCompressor(cctx, compressor);
    if (ZL_isError(report)) {
        result = set_cctx_error(cctx, "ZL_CCtx_refCompressor", report);
        goto cleanup;
    }

    for (; nb_refs < nb_inputs; nb_refs++) {
        refs[nb_refs] = typed_ref(&inputs[nb_refs]);
        if (refs[nb_refs] == NULL) {
            set_error_message("ZL_TypedRef creation failed");
            goto cleanup;
        }
    }

    report = ZL_CCtx_compressMultiTypedRef(
            cctx, dst, dst_capacity, refs, nb_inputs);
    if (ZL_isError(report)) {
        result = set_cctx_error(cctx, "ZL_CCtx_compressMultiTypedRef", report);
        goto cleanup;
    }
    *written = ZL_validResult(report);
    result   = 0;

cleanup:
    for (size_t i = 0; i < nb_refs; i++) {
        ZL_TypedRef_free((ZL_TypedRef*)refs[i]);
    }
    ZL_CCtx_free(cctx);
    ZL_Compressor_free(compressor);
    return result;
}

size_t ozlrip_shim_compress_bound(size_t total_input_size)
{
    return ZL_compressBound(total_input_size);
}
