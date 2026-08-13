package org.example.cameraruntimeprobe;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import android.graphics.ImageDecoder;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.TotalCaptureResult;
import android.media.Image;
import android.media.ExifInterface;
import android.media.ImageReader;
import android.os.Handler;
import android.view.Surface;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class CameraSupport {
    static final long TIMEOUT_SECONDS = 15L;
    static final int SAMPLE_WIDTH = 16;
    static final int SAMPLE_HEIGHT = 12;
    static final int SAMPLE_CHANNELS = 3;
    static final int SAMPLE_BYTES = SAMPLE_WIDTH * SAMPLE_HEIGHT * SAMPLE_CHANNELS;


    private CameraSupport() {}

    static CameraDevice open(CameraManager manager, String id, Handler handler) throws Exception {
        CountDownLatch terminal = new CountDownLatch(1);
        AtomicReference<CameraDevice> opened = new AtomicReference<>();
        AtomicReference<String> error = new AtomicReference<>();
        manager.openCamera(id, new CameraDevice.StateCallback() {
            @Override public void onOpened(CameraDevice camera) {
                opened.set(camera);
                terminal.countDown();
            }
            @Override public void onDisconnected(CameraDevice camera) {
                error.compareAndSet(null, "disconnected");
                camera.close();
                terminal.countDown();
            }
            @Override public void onError(CameraDevice camera, int code) {
                error.compareAndSet(null, "open error");
                camera.close();
                terminal.countDown();
            }
        }, handler);
        if (!terminal.await(TIMEOUT_SECONDS, TimeUnit.SECONDS) || opened.get() == null) {
            throw new IllegalStateException(error.get() == null ? "open timeout" : error.get());
        }
        return opened.get();
    }

    static CameraCaptureSession configure(CameraDevice device, List<Surface> surfaces,
            Handler handler) throws Exception {
        CountDownLatch terminal = new CountDownLatch(1);
        AtomicReference<CameraCaptureSession> configured = new AtomicReference<>();
        device.createCaptureSession(surfaces, new CameraCaptureSession.StateCallback() {
            @Override public void onConfigured(CameraCaptureSession session) {
                configured.set(session);
                terminal.countDown();
            }
            @Override public void onConfigureFailed(CameraCaptureSession session) {
                terminal.countDown();
            }
        }, handler);
        if (!terminal.await(TIMEOUT_SECONDS, TimeUnit.SECONDS) || configured.get() == null) {
            throw new IllegalStateException("configure timeout");
        }
        return configured.get();
    }

    static TotalCaptureResult captureResult(
            CameraCaptureSession session, CaptureRequest request, Handler handler)
            throws Exception {
        CountDownLatch terminal = new CountDownLatch(1);
        AtomicReference<TotalCaptureResult> result = new AtomicReference<>();
        AtomicReference<String> error = new AtomicReference<>();
        session.capture(request, new CameraCaptureSession.CaptureCallback() {
            @Override public void onCaptureCompleted(CameraCaptureSession value,
                    CaptureRequest captureRequest, TotalCaptureResult captureResult) {
                result.set(captureResult);
                terminal.countDown();
            }
            @Override public void onCaptureFailed(CameraCaptureSession value,
                    CaptureRequest captureRequest, CaptureFailure failure) {
                error.set("capture failed");
                terminal.countDown();
            }
        }, handler);
        if (!terminal.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)
                || result.get() == null) {
            throw new IllegalStateException(
                    error.get() == null ? "capture timeout" : error.get());
        }
        return result.get();
    }

    static long capture(CameraCaptureSession session, CaptureRequest request, Handler handler)
            throws Exception {
        Long timestamp = captureResult(session, request, handler).get(
                android.hardware.camera2.CaptureResult.SENSOR_TIMESTAMP);
        if (timestamp == null) throw new IllegalStateException("capture timestamp missing");
        return timestamp;
    }

    static final class Frame {
        final long fingerprint;
        final int bytes;
        final long timestamp;
        final boolean jpegValid;
        final boolean jpegExifValid;
        final byte[] sample;

        Frame(long fingerprint, int bytes, long timestamp, boolean jpegValid,
                boolean jpegExifValid, byte[] sample) {
            this.fingerprint = fingerprint;
            this.bytes = bytes;
            this.timestamp = timestamp;
            this.jpegValid = jpegValid;
            this.jpegExifValid = jpegExifValid;
            this.sample = sample;
        }
    }

    static final class FrameReader implements AutoCloseable {
        final ImageReader reader;
        final LinkedBlockingQueue<Frame> frames = new LinkedBlockingQueue<>();
        final AtomicReference<String> error = new AtomicReference<>();
        private final int format;

        FrameReader(int width, int height, int format, int maxImages, Handler handler) {
            this.format = format;
            reader = ImageReader.newInstance(width, height, format, maxImages);
            reader.setOnImageAvailableListener(this::available, handler);
        }

        Surface surface() { return reader.getSurface(); }

        Frame take() throws Exception {
            Frame frame = frames.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (frame == null) {
                throw new IllegalStateException(error.get() == null ? "image timeout" : error.get());
            }
            return frame;
        }

        void clear() { frames.clear(); }

        private void available(ImageReader source) {
            try (Image image = source.acquireNextImage()) {
                if (image == null) return;
                long value = 0xcbf29ce484222325L;
                int byteCount = 0;
                boolean jpegValid = format != ImageFormat.JPEG;
                byte[] sample = new byte[0];
                Image.Plane[] planes = image.getPlanes();
                if (format == ImageFormat.PRIVATE) {
                    frames.offer(new Frame(
                            value, 0, image.getTimestamp(), true, true, sample));
                    return;
                }
                if (format == ImageFormat.JPEG) {
                    if (planes.length != 1) throw new IllegalStateException("JPEG plane mismatch");
                    ByteBuffer data = planes[0].getBuffer().duplicate();
                    byte[] encoded = new byte[data.remaining()];
                    data.get(encoded);
                    byteCount = encoded.length;
                    int start = encoded.length >= 2
                            ? ((encoded[0] & 0xff) << 8) | (encoded[1] & 0xff) : 0;
                    int end = encoded.length >= 2
                            ? ((encoded[encoded.length - 2] & 0xff) << 8)
                                    | (encoded[encoded.length - 1] & 0xff) : 0;
                    Bitmap bitmap = BitmapFactory.decodeByteArray(encoded, 0, encoded.length);
                    jpegValid = start == 0xffd8 && end == 0xffd9 && bitmap != null;
                    boolean jpegExifValid = bitmap != null
                            && hasExpectedExif(encoded, bitmap);
                    if (bitmap != null) {
                        sample = sampleBitmap(bitmap);
                        int[] pixels = new int[bitmap.getWidth() * bitmap.getHeight()];
                        bitmap.getPixels(pixels, 0, bitmap.getWidth(), 0, 0,
                                bitmap.getWidth(), bitmap.getHeight());
                        for (int pixel : pixels) {
                            value ^= pixel & 0xffffffffL;
                            value *= 0x100000001b3L;
                        }
                        bitmap.recycle();
                    }
                    frames.offer(new Frame(value, byteCount, image.getTimestamp(),
                            jpegValid, jpegExifValid, sample));
                    return;
                }

                Rect crop = image.getCropRect();
                for (int planeIndex = 0; planeIndex < planes.length; ++planeIndex) {
                    Image.Plane plane = planes[planeIndex];
                    ByteBuffer data = plane.getBuffer().duplicate();
                    int subsample = planeIndex == 0 ? 1 : 2;
                    int left = crop.left / subsample;
                    int top = crop.top / subsample;
                    int width = (crop.width() + subsample - 1) / subsample;
                    int height = (crop.height() + subsample - 1) / subsample;
                    for (int y = 0; y < height; ++y) {
                        for (int x = 0; x < width; ++x) {
                            int offset = data.position()
                                    + (top + y) * plane.getRowStride()
                                    + (left + x) * plane.getPixelStride();
                            if (offset < data.position() || offset >= data.limit()) {
                                throw new IllegalStateException("YUV plane bounds");
                            }
                            value ^= data.get(offset) & 0xffL;
                            value *= 0x100000001b3L;
                            ++byteCount;
                        }
                    }
                }
                if (planes.length >= 3 && crop.width() > 0 && crop.height() > 0) {
                    sample = sampleYuv(planes, crop);
                }
                frames.offer(new Frame(value, byteCount, image.getTimestamp(),
                        jpegValid, true, sample));
            } catch (Throwable failure) {
                error.compareAndSet(null, failure.getClass().getSimpleName());
            }
        }

        private static boolean hasExpectedExif(byte[] encoded, Bitmap bitmap) {
            try {
                ExifInterface exif = new ExifInterface(new ByteArrayInputStream(encoded));
                String dateTime = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL);
                String subsecond = exif.getAttribute(ExifInterface.TAG_SUBSEC_TIME_ORIGINAL);
                String make = exif.getAttribute(ExifInterface.TAG_MAKE);
                String model = exif.getAttribute(ExifInterface.TAG_MODEL);
                String exposureBias =
                        exif.getAttribute(ExifInterface.TAG_EXPOSURE_BIAS_VALUE);
                String whiteBalance = exif.getAttribute(ExifInterface.TAG_WHITE_BALANCE);
                return exif.getAttributeInt(
                                ExifInterface.TAG_ORIENTATION,
                                ExifInterface.ORIENTATION_UNDEFINED)
                                == ExifInterface.ORIENTATION_NORMAL
                        && exif.getAttributeInt(ExifInterface.TAG_PIXEL_X_DIMENSION, -1)
                                == bitmap.getWidth()
                        && exif.getAttributeInt(ExifInterface.TAG_PIXEL_Y_DIMENSION, -1)
                                == bitmap.getHeight()
                        && dateTime != null && !dateTime.isEmpty()
                        && subsecond != null && !subsecond.isEmpty()
                        && make != null && !make.isEmpty()
                        && model != null && !model.isEmpty()
                        && exif.getAttributeDouble(ExifInterface.TAG_EXPOSURE_TIME, -1.0)
                                > 0.0
                        && exif.getAttributeInt(
                                ExifInterface.TAG_ISO_SPEED_RATINGS, -1) > 0
                        && exif.getAttributeDouble(ExifInterface.TAG_FOCAL_LENGTH, -1.0)
                                > 0.0
                        && exposureBias != null && whiteBalance != null
                        && exif.getAttribute(ExifInterface.TAG_GPS_LATITUDE) == null
                        && exif.getAttribute(ExifInterface.TAG_GPS_LONGITUDE) == null
                        && exif.getAttribute(ExifInterface.TAG_ARTIST) == null
                        && exif.getAttribute(ExifInterface.TAG_COPYRIGHT) == null
                        && exif.getAttribute(ExifInterface.TAG_USER_COMMENT) == null
                        && exif.getAttribute(ExifInterface.TAG_MAKER_NOTE) == null;
            } catch (Throwable ignored) {
                return false;
            }
        }

        private static byte[] sampleYuv(Image.Plane[] planes, Rect crop) {
            byte[] sample = new byte[SAMPLE_BYTES];
            ByteBuffer yData = planes[0].getBuffer().duplicate();
            ByteBuffer uData = planes[1].getBuffer().duplicate();
            ByteBuffer vData = planes[2].getBuffer().duplicate();
            for (int y = 0; y < SAMPLE_HEIGHT; ++y) {
                int sourceY = crop.top
                        + ((2 * y + 1) * crop.height()) / (2 * SAMPLE_HEIGHT);
                sourceY = Math.min(crop.bottom - 1, sourceY);
                for (int x = 0; x < SAMPLE_WIDTH; ++x) {
                    int sourceX = crop.left
                            + ((2 * x + 1) * crop.width()) / (2 * SAMPLE_WIDTH);
                    sourceX = Math.min(crop.right - 1, sourceX);
                    int yValue = planeByte(planes[0], yData, sourceX, sourceY, "Y");
                    int uValue = planeByte(
                            planes[1], uData, sourceX / 2, sourceY / 2, "U");
                    int vValue = planeByte(
                            planes[2], vData, sourceX / 2, sourceY / 2, "V");
                    int c = Math.max(0, yValue - 16);
                    int d = uValue - 128;
                    int e = vValue - 128;
                    int red = clampRgb((298 * c + 409 * e + 128) >> 8);
                    int green = clampRgb((298 * c - 100 * d - 208 * e + 128) >> 8);
                    int blue = clampRgb((298 * c + 516 * d + 128) >> 8);
                    int offset = (y * SAMPLE_WIDTH + x) * SAMPLE_CHANNELS;
                    sample[offset] = (byte) red;
                    sample[offset + 1] = (byte) green;
                    sample[offset + 2] = (byte) blue;
                }
            }
            return sample;
        }

        private static int planeByte(Image.Plane plane, ByteBuffer data,
                int x, int y, String name) {
            int offset = data.position() + y * plane.getRowStride()
                    + x * plane.getPixelStride();
            if (offset < data.position() || offset >= data.limit()) {
                throw new IllegalStateException(name + " sample bounds");
            }
            return data.get(offset) & 0xff;
        }

        private static int clampRgb(int value) {
            return Math.max(0, Math.min(255, value));
        }

        private static byte[] sampleBitmap(Bitmap bitmap) {
            byte[] sample = new byte[SAMPLE_BYTES];
            for (int y = 0; y < SAMPLE_HEIGHT; ++y) {
                int sourceY = ((2 * y + 1) * bitmap.getHeight())
                        / (2 * SAMPLE_HEIGHT);
                sourceY = Math.min(bitmap.getHeight() - 1, sourceY);
                for (int x = 0; x < SAMPLE_WIDTH; ++x) {
                    int sourceX = ((2 * x + 1) * bitmap.getWidth())
                            / (2 * SAMPLE_WIDTH);
                    sourceX = Math.min(bitmap.getWidth() - 1, sourceX);
                    int pixel = bitmap.getPixel(sourceX, sourceY);
                    int offset = (y * SAMPLE_WIDTH + x) * SAMPLE_CHANNELS;
                    sample[offset] = (byte) ((pixel >>> 16) & 0xff);
                    sample[offset + 1] = (byte) ((pixel >>> 8) & 0xff);
                    sample[offset + 2] = (byte) (pixel & 0xff);
                }
            }
            return sample;
        }

        @Override public void close() { reader.close(); }
    }

    static byte[] referencePhotoSample(String path, int outputWidth, int outputHeight,
            int rotationDegrees) throws Exception {
        Bitmap bitmap = ImageDecoder.decodeBitmap(
                ImageDecoder.createSource(new File(path)),
                (decoder, info, source) ->
                        decoder.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE));
        if (bitmap == null) throw new IllegalStateException("reference photo decode failed");
        try {
            return transformedBitmapSample(
                    bitmap, outputWidth, outputHeight, rotationDegrees);
        } finally {
            bitmap.recycle();
        }
    }

    static byte[] referencePhotoSample(String path, int outputWidth, int outputHeight,
            int rotationDegrees, boolean mirrored) throws Exception {
        Bitmap bitmap = ImageDecoder.decodeBitmap(
                ImageDecoder.createSource(new File(path)),
                (decoder, info, source) ->
                        decoder.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE));
        if (bitmap == null) throw new IllegalStateException("reference photo decode failed");
        try {
            return transformedBitmapSample(
                    bitmap, outputWidth, outputHeight, rotationDegrees, mirrored);
        } finally {
            bitmap.recycle();
        }
    }

    static byte[] transformedBitmapSample(Bitmap bitmap, int outputWidth, int outputHeight,
            int rotationDegrees) {
        return transformedBitmapSample(
                bitmap, outputWidth, outputHeight, rotationDegrees, false);
    }

    static byte[] transformedBitmapSample(Bitmap bitmap, int outputWidth, int outputHeight,
            int rotationDegrees, boolean mirrored) {
        int rotation = ((rotationDegrees % 360) + 360) % 360;
        if (rotation % 90 != 0) {
            throw new IllegalArgumentException("reference rotation must be a right angle");
        }
        int sourceWidth = bitmap.getWidth();
        int sourceHeight = bitmap.getHeight();
        boolean swapsAxes = rotation == 90 || rotation == 270;
        int orientedWidth = swapsAxes ? sourceHeight : sourceWidth;
        int orientedHeight = swapsAxes ? sourceWidth : sourceHeight;
        double scaleX = (double) outputWidth / orientedWidth;
        double scaleY = (double) outputHeight / orientedHeight;
        byte[] sample = new byte[SAMPLE_BYTES];
        for (int y = 0; y < SAMPLE_HEIGHT; ++y) {
            double outputY = ((2.0 * y + 1.0) * outputHeight)
                    / (2.0 * SAMPLE_HEIGHT);
            double orientedY = (outputY - outputHeight * 0.5) / scaleY
                    + (orientedHeight - 1) * 0.5;
            orientedY = Math.max(0.0, Math.min(orientedHeight - 1.0, orientedY));
            for (int x = 0; x < SAMPLE_WIDTH; ++x) {
                double outputX = ((2.0 * x + 1.0) * outputWidth)
                        / (2.0 * SAMPLE_WIDTH);
                if (mirrored) outputX = outputWidth - outputX;
                double orientedX = (outputX - outputWidth * 0.5) / scaleX
                        + (orientedWidth - 1) * 0.5;
                orientedX = Math.max(0.0, Math.min(orientedWidth - 1.0, orientedX));
                double sourceX;
                double sourceY;
                switch (rotation) {
                    case 90:
                        sourceX = orientedY;
                        sourceY = sourceHeight - 1.0 - orientedX;
                        break;
                    case 180:
                        sourceX = sourceWidth - 1.0 - orientedX;
                        sourceY = sourceHeight - 1.0 - orientedY;
                        break;
                    case 270:
                        sourceX = sourceWidth - 1.0 - orientedY;
                        sourceY = orientedX;
                        break;
                    default:
                        sourceX = orientedX;
                        sourceY = orientedY;
                        break;
                }
                int pixelX = Math.max(0, Math.min(sourceWidth - 1,
                        (int) Math.floor(sourceX)));
                int pixelY = Math.max(0, Math.min(sourceHeight - 1,
                        (int) Math.floor(sourceY)));
                int pixel = bitmap.getPixel(pixelX, pixelY);
                int offset = (y * SAMPLE_WIDTH + x) * SAMPLE_CHANNELS;
                sample[offset] = (byte) ((pixel >>> 16) & 0xff);
                sample[offset + 1] = (byte) ((pixel >>> 8) & 0xff);
                sample[offset + 2] = (byte) (pixel & 0xff);
            }
        }
        return sample;
    }

    static double meanDelta(byte[] first, byte[] second) {
        if (first.length == 0 || first.length != second.length) {
            return Double.POSITIVE_INFINITY;
        }
        long total = 0;
        for (int index = 0; index < first.length; ++index) {
            total += Math.abs((first[index] & 0xff) - (second[index] & 0xff));
        }
        return ((double) total) / first.length;
    }
}
