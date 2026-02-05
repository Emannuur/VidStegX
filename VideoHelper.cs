using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using FFMediaToolkit;
using FFMediaToolkit.Decoding;
using FFMediaToolkit.Encoding;
using FFMediaToolkit.Graphics;

namespace VidStegX.Models
{
    public class VideoInfo
    {
        public int Width { get; set; }
        public int Height { get; set; }
        public int FrameRate { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public static class VideoHelper
    {
        private static bool _ffmpegInitialized = false;
        private static string? _ffmpegPath = null;

        static VideoHelper()
        {
            InitializeFFmpeg();
        }

        private static void InitializeFFmpeg()
        {
            if (_ffmpegInitialized) return;

            try
            {
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                
                string[] possiblePaths = new[]
                {
                    Path.Combine(baseDir, "ffmpeg"),
                    Path.Combine(baseDir, "runtimes", RuntimeInformation.RuntimeIdentifier, "native"),
                    Path.Combine(baseDir, "runtimes", Environment.Is64BitProcess ? "win-x64" : "win-x86", "native"),
                    Path.Combine(baseDir, "runtimes", "win-x64", "native"),
                    baseDir
                };

                foreach (var path in possiblePaths)
                {
                    if (Directory.Exists(path))
                    {
                        var ffmpegFiles = Directory.GetFiles(path, "avcodec*.dll");
                        if (ffmpegFiles.Length > 0)
                        {
                            FFmpegLoader.FFmpegPath = path;
                            _ffmpegPath = path;
                            _ffmpegInitialized = true;
                            return;
                        }
                    }
                }
                _ffmpegInitialized = true;
            }
            catch
            {
                _ffmpegInitialized = true;
            }
        }

        /// <summary>
        /// Loads frames from video file.
        /// This method works correctly and is used by VideoHelperFFmpeg.
        /// </summary>
        public static List<Bitmap> LoadFrames(string videoPath, int maxWidth = 0, int maxHeight = 0)
        {
            if (!File.Exists(videoPath))
                throw new FileNotFoundException($"Video file not found: {videoPath}");

            var frames = new List<Bitmap>();

            try
            {
                using (var file = MediaFile.Open(videoPath))
                {
                    var originalSize = file.Video.Info.FrameSize;
                    
                    System.Drawing.Size targetSize;
                    
                    if (maxWidth > 0 && maxHeight > 0)
                    {
                        targetSize = CalculateAspectRatioSize(originalSize.Width, originalSize.Height, maxWidth, maxHeight);
                    }
                    else
                    {
                        targetSize = new System.Drawing.Size(originalSize.Width, originalSize.Height);
                    }

                    // Ensure even dimensions
                    if (targetSize.Width % 2 != 0) targetSize.Width++;
                    if (targetSize.Height % 2 != 0) targetSize.Height++;

                    while (file.Video.TryGetNextFrame(out var imageData))
                    {
                        var bitmap = ConvertToBitmap(imageData);
                        
                        if (bitmap.Width != targetSize.Width || bitmap.Height != targetSize.Height)
                        {
                            using (bitmap)
                            {
                                frames.Add(new Bitmap(bitmap, targetSize.Width, targetSize.Height));
                            }
                        }
                        else
                        {
                            frames.Add(bitmap);
                        }
                    }
                }
            }
            catch (DllNotFoundException ex)
            {
                throw new Exception("FFmpeg libraries not found. Please rebuild the project.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error loading video: {ex.Message}", ex);
            }

            if (frames.Count == 0)
                throw new Exception("No frames could be loaded from the video file.");

            return frames;
        }

        public static VideoInfo GetVideoInfo(string videoPath)
        {
            if (!File.Exists(videoPath))
                throw new FileNotFoundException($"Video file not found: {videoPath}");

            try
            {
                using (var file = MediaFile.Open(videoPath))
                {
                    return new VideoInfo
                    {
                        Width = file.Video.Info.FrameSize.Width,
                        Height = file.Video.Info.FrameSize.Height,
                        FrameRate = (int)file.Video.Info.AvgFrameRate,
                        Duration = file.Info.Duration
                    };
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error reading video info: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// DEPRECATED: Use VideoHelperFFmpeg.SaveLosslessAVI() instead.
        /// This method uses MPEG4 codec which is LOSSY and corrupts LSB data.
        /// </summary>
        [Obsolete("Use VideoHelperFFmpeg.SaveLosslessAVI() for true lossless encoding")]
        public static void SaveFrames(string outputPath, List<Bitmap> frames, int frameRate = 24)
        {
            throw new NotSupportedException(
                "SaveFrames() with MPEG4 codec is deprecated because it destroys LSB data. " +
                "Use VideoHelperFFmpeg.SaveLosslessAVI() instead for truly lossless FFV1 encoding.");
        }

        // Replace the ConvertToBitmap method with this corrected version

        private static Bitmap ConvertToBitmap(ImageData imageData)
        {
            var bitmap = new Bitmap(imageData.ImageSize.Width, imageData.ImageSize.Height, PixelFormat.Format24bppRgb);
            var rect = new Rectangle(0, 0, bitmap.Width, bitmap.Height);
            var bitmapData = bitmap.LockBits(rect, ImageLockMode.WriteOnly, bitmap.PixelFormat);

            try
            {
                int stride = bitmapData.Stride;
                int dataStride = imageData.Stride;

                unsafe
                {
                    byte* destPtr = (byte*)bitmapData.Scan0;
                    var sourceData = imageData.Data;

                    for (int y = 0; y < bitmap.Height; y++)
                    {
                        int destOffset = y * stride;
                        int sourceOffset = y * dataStride;

                        for (int x = 0; x < bitmap.Width; x++)
                        {
                            int destIdx = destOffset + (x * 3);
                            int sourceIdx = sourceOffset + (x * 3);

                            // FFMediaToolkit usually returns BGR24 for videos ? direct copy preserves LSB
                            destPtr[destIdx] = sourceData[sourceIdx];     // B
                            destPtr[destIdx + 1] = sourceData[sourceIdx + 1]; // G
                            destPtr[destIdx + 2] = sourceData[sourceIdx + 2]; // R
                        }
                    }
                }
            }
            finally
            {
                bitmap.UnlockBits(bitmapData);
            }

            return bitmap;
        }

        private static System.Drawing.Size CalculateAspectRatioSize(int originalWidth, int originalHeight, int maxWidth, int maxHeight)
        {
            double aspectRatio = (double)originalWidth / originalHeight;
            int newWidth = maxWidth;
            int newHeight = (int)(maxWidth / aspectRatio);

            if (newHeight > maxHeight)
            {
                newHeight = maxHeight;
                newWidth = (int)(maxHeight * aspectRatio);
            }

            return new System.Drawing.Size(newWidth, newHeight);
        }
    }
}
