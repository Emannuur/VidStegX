using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Threading.Tasks;

namespace VidStegX.Models
{
    using GdiBitmap = System.Drawing.Bitmap;

    public static class VideoHelperFFmpeg
    {
        private static string GetFFmpegExePath()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            string[] possiblePaths = new[]
            {
                Path.Combine(baseDir, "ffmpeg", "ffmpeg.exe"),
                Path.Combine(baseDir, "ffmpeg.exe"),
                "ffmpeg.exe"
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                    return path;
            }

            throw new FileNotFoundException("ffmpeg.exe not found.");
        }

        public static void SaveLosslessAVI(
            string outputPath,
            List<GdiBitmap> frames,
            int frameRate = 24,
            string? originalVideoPath = null)
        {
            if (frames == null || frames.Count == 0)
                throw new ArgumentException("No frames to save");

            outputPath = Path.ChangeExtension(outputPath, ".avi");

            string tempDir = Path.Combine(Path.GetTempPath(), $"vidstegx_temp_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            try
            {
                // Clone frames first (main thread)
                List<GdiBitmap> clonedFrames = new(frames.Count);
                for (int i = 0; i < frames.Count; i++)
                    clonedFrames.Add((GdiBitmap)frames[i].Clone());

                // Parallel save
                var saveTasks = new Task[clonedFrames.Count];
                for (int i = 0; i < clonedFrames.Count; i++)
                {
                    int index = i;
                    saveTasks[i] = Task.Run(() =>
                    {
                        string bmpPath = Path.Combine(tempDir, $"frame_{index:D6}.bmp");
                        clonedFrames[index].Save(bmpPath, ImageFormat.Bmp);
                    });
                }

                Task.WaitAll(saveTasks);

                string ffmpegExe = GetFFmpegExePath();
                string inputPattern = Path.Combine(tempDir, "frame_%06d.bmp");

                string arguments;

                // If original video exists, try to copy its audio (if any)
                if (!string.IsNullOrEmpty(originalVideoPath) && File.Exists(originalVideoPath))
                {
                    // -map 0:a?  optional audio, no explicit -c:a copy to avoid errors when no audio
                    arguments =
                        $"-i \"{originalVideoPath}\" -i \"{inputPattern}\" " +
                        "-map 0:a? -map 1:v -c:v ffv1 -pix_fmt bgr24 -y \"" + outputPath + "\"";
                }
                else
                {
                    arguments =
                        $"-framerate {frameRate} -i \"{inputPattern}\" " +
                        "-c:v ffv1 -pix_fmt bgr24 -y \"" + outputPath + "\"";
                }

                var processInfo = new ProcessStartInfo
                {
                    FileName = ffmpegExe,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(processInfo))
                {
                    if (process == null)
                        throw new Exception("Failed to start FFmpeg process.");

                    string stderr = process.StandardError.ReadToEnd();
                    string stdout = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0)
                    {
                        throw new Exception(
                            $"FFmpeg failed (code {process.ExitCode}).\n" +
                            $"Args: {arguments}\n\nSTDERR:\n{stderr}\n\nSTDOUT:\n{stdout}");
                    }
                }

                if (!File.Exists(outputPath))
                    throw new Exception("Output not created");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempDir))
                        Directory.Delete(tempDir, true);
                }
                catch { }
            }
        }

        public static List<GdiBitmap> LoadFrames(string videoPath, int maxWidth = 0, int maxHeight = 0)
        {
            return VideoHelper.LoadFrames(videoPath, maxWidth, maxHeight)
                .ConvertAll(b => (GdiBitmap)b);
        }

        public static VideoInfo GetVideoInfo(string videoPath)
        {
            return VideoHelper.GetVideoInfo(videoPath);
        }
    }
}
