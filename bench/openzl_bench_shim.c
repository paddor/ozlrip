#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "openzl/openzl.h"

static _Thread_local char OZLRIP_OPENZL_LAST_ERROR[8192];

static int ozlrip_bench_report_code(ZL_Report report) {
    return (int)ZL_errorCode(report);
}

static int ozlrip_bench_set_error(ZL_DCtx* dctx, const char* message, ZL_Report report) {
    int const code = ozlrip_bench_report_code(report);
    const char* const name = ZL_ErrorCode_toString((ZL_ErrorCode)code);
    const char* const context = ZL_DCtx_getErrorContextString(dctx, report);
    snprintf(
            OZLRIP_OPENZL_LAST_ERROR,
            sizeof(OZLRIP_OPENZL_LAST_ERROR),
            "%s: code=%d %s; context=%s",
            message,
            code,
            name ? name : "<null>",
            context ? context : "<null>");
    return code;
}

ZL_DCtx* ozlrip_bench_openzl_dctx_create(void) {
    return ZL_DCtx_create();
}

void ozlrip_bench_openzl_dctx_free(ZL_DCtx* dctx) {
    ZL_DCtx_free(dctx);
}

const char* ozlrip_bench_openzl_last_error(void) {
    return OZLRIP_OPENZL_LAST_ERROR;
}

int ozlrip_bench_openzl_dctx_disable_checksums(ZL_DCtx* dctx) {
    ZL_Report report = ZL_DCtx_setParameter(dctx, ZL_DParam_stickyParameters, 1);
    if (ZL_isError(report)) {
        return ozlrip_bench_set_error(dctx, "ZL_DCtx_setParameter(sticky)", report);
    }
    report = ZL_DCtx_setParameter(
            dctx,
            ZL_DParam_checkCompressedChecksum,
            ZL_TernaryParam_disable);
    if (ZL_isError(report)) {
        return ozlrip_bench_set_error(
                dctx, "ZL_DCtx_setParameter(compressed checksum)", report);
    }
    report = ZL_DCtx_setParameter(
            dctx,
            ZL_DParam_checkContentChecksum,
            ZL_TernaryParam_disable);
    if (ZL_isError(report)) {
        return ozlrip_bench_set_error(
                dctx, "ZL_DCtx_setParameter(content checksum)", report);
    }
    return 0;
}

int ozlrip_bench_openzl_decompress_serial(
        ZL_DCtx* dctx,
        void* dst,
        size_t dst_capacity,
        const void* src,
        size_t src_size,
        size_t* written) {
    ZL_TypedBuffer* const output = ZL_TypedBuffer_createWrapSerial(dst, dst_capacity);
    if (output == NULL) {
        snprintf(
                OZLRIP_OPENZL_LAST_ERROR,
                sizeof(OZLRIP_OPENZL_LAST_ERROR),
                "ZL_TypedBuffer_createWrapSerial returned NULL");
        return -1;
    }

    ZL_Report const report = ZL_DCtx_decompressTBuffer(dctx, output, src, src_size);
    ZL_TypedBuffer_free(output);
    if (ZL_isError(report)) {
        return ozlrip_bench_set_error(dctx, "ZL_DCtx_decompressTBuffer", report);
    }
    *written = ZL_validResult(report);
    return 0;
}
