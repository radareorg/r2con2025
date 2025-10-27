/*
 * css_cam.h
 *
 * Suggested header for libcss camera API based on exported symbols:
 *   CSS_CAM_Open
 *   CSS_CAM_Close
 *   CSS_CAM_Init
 *   CSS_CAM_Deinit
 *   CSS_CAM_Activate
 *   CSS_CAM_Deactivate
 *   CSS_CAM_PowerOn
 *   CSS_CAM_PowerOff
 *   CSS_CAM_IsOpened
 *   CSS_CAM_GetImage
 *
 * NOTE: This is a reverse-engineered / guessed header. Verify enums,
 * return values and calling convention against the real library.
 */

#ifndef CSS_CAM_H
#define CSS_CAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Export macro: adapt for Windows DLL import/export if necessary */
#ifndef CSS_API
# ifdef _WIN32
#  ifdef CSS_CAM_BUILD
#   define CSS_API __declspec(dllexport)
#  else
#   define CSS_API __declspec(dllimport)
#  endif
# else
#  define CSS_API
# endif
#endif

/* Common return codes */
typedef enum {
    CSS_CAM_OK = 0,
    CSS_CAM_ERR = -1,
    CSS_CAM_ERR_INVALID_ARG = -2,
    CSS_CAM_ERR_NOT_INITIALIZED = -3,
    CSS_CAM_ERR_NOT_OPEN = -4,
    CSS_CAM_ERR_NO_MEMORY = -5,
    CSS_CAM_ERR_BUFFER_TOO_SMALL = -6,
    /* add other codes as needed */
} CssCamStatus_e;

/* Camera device index (example list) */
typedef enum {
    CSS_CAM_DEV_0 = 0,
    CSS_CAM_DEV_1 = 1,
    CSS_CAM_DEV_2 = 2,
    CSS_CAM_DEV_MAX
} CssCamDevIdx_e;

/* Action mode: guessed meanings */
typedef enum {
    CSS_CAM_ACTION_NONE = 0,
    CSS_CAM_ACTION_START = 1,
    CSS_CAM_ACTION_STOP = 2,
    CSS_CAM_ACTION_PAUSE = 3,
    CSS_CAM_ACTION_RESUME = 4
} CssCamActionMode_e;

/* Capture mode: single frame vs continuous (guessed) */
typedef enum {
    CSS_CAM_CAPTURE_SINGLE = 0,
    CSS_CAM_CAPTURE_CONTINUOUS = 1
} CssCamCaptureMode_e;

/* Pixel formats (guessed) */
typedef enum {
    CSS_CAM_PIX_FMT_UNKNOWN = 0,
    CSS_CAM_PIX_FMT_RGB24 = 1,   /* 3 bytes per pixel */
    CSS_CAM_PIX_FMT_BGR24 = 2,
    CSS_CAM_PIX_FMT_GRAY8 = 3,
    CSS_CAM_PIX_FMT_YUV420 = 4
} CssCamPixelFormat_e;

/*
 * Initialize camera system for device 'dev'.
 * Returns CSS_CAM_OK on success.
 */
CSS_API int CSS_CAM_Init(CssCamDevIdx_e dev);

/*
 * Deinitialize camera system for device 'dev'.
 */
CSS_API int CSS_CAM_Deinit(CssCamDevIdx_e dev);

/*
 * Open camera device. Typically opens hardware or driver.
 */
CSS_API int CSS_CAM_Open(CssCamDevIdx_e dev);

/*
 * Close camera device.
 */
CSS_API int CSS_CAM_Close(CssCamDevIdx_e dev);

/*
 * Power on the camera device (if supported).
 */
CSS_API int CSS_CAM_PowerOn(CssCamDevIdx_e dev);

/*
 * Power off the camera device.
 */
CSS_API int CSS_CAM_PowerOff(CssCamDevIdx_e dev);

/*
 * Activate camera streaming/capture.
 * action - action mode (start/stop/etc)
 * cap_mode - capture mode (single/continuous)
 * pixfmt - desired pixel format
 */
CSS_API int CSS_CAM_Activate(CssCamDevIdx_e dev,
                             CssCamActionMode_e action,
                             CssCamCaptureMode_e cap_mode,
                             CssCamPixelFormat_e pixfmt);

/*
 * Deactivate streaming/capture.
 */
CSS_API int CSS_CAM_Deactivate(CssCamDevIdx_e dev);

/*
 * Check whether device is opened.
 * out_is_opened should be non-NULL; receives true if opened.
 */
CSS_API int CSS_CAM_IsOpened(CssCamDevIdx_e dev, bool *out_is_opened);

/*
 * Get image data into buffer.
 * buffer: pointer to destination buffer
 * buf_size: size of destination buffer in bytes
 *
 * Return value semantics are guessed:
 *   >0 : number of bytes written to buffer (success)
 *    0 : no data available or zero-size frame
 *   <0 : negative error code (see CssCamStatus_e)
 *
 * If the real API returns an error code only (not bytes), adapt accordingly.
 */
CSS_API int CSS_CAM_GetImage(CssCamDevIdx_e dev, void *buffer, size_t buf_size);


#ifdef __cplusplus
}
#endif

#endif /* CSS_CAM_H */
