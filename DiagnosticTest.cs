using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using VidStegX.Models;

namespace VidStegX.Tests
{
    using GdiBitmap = System.Drawing.Bitmap;

    public static class DiagnosticTest
    {
        public static void RunDiagnostics()
        {
            Console.WriteLine("=== STEGANOGRAPHY DIAGNOSTIC TEST ===\n");

            Test_DirectEmbedExtract();
            Test_WithVideoCodec();
            Test_BitCorruption();

            Console.WriteLine("\n=== DIAGNOSTICS COMPLETE ===");
        }

        static void Test_DirectEmbedExtract()
        {
            Console.WriteLine("Test 1: Direct Embed/Extract (No Video Codec)");
            Console.WriteLine("----------------------------------------------");

            try
            {
                var frames = CreateTestFrames(10, 320, 240);
                string message = "Test Message 123";
                string key = "TestKey";

                Console.WriteLine($"Original message: '{message}'");

                var stegoFrames = StegoCore.EmbedVideo(frames, message, key);
                Console.WriteLine("? Embedding successful");

                var result = StegoCore.ExtractVideo(stegoFrames, key);
                string extracted = result.Message;

                if (extracted == message)
                {
                    Console.WriteLine("? PASSED: Direct embed/extract works perfectly!");
                }
                else
                {
                    Console.WriteLine($"? FAILED: Message mismatch");
                    Console.WriteLine($" Expected: '{message}'");
                    Console.WriteLine($" Got: '{extracted}'");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
                Console.WriteLine($" Stack: {ex.StackTrace}");
            }

            Console.WriteLine();
        }

        static void Test_WithVideoCodec()
        {
            Console.WriteLine("Test 2: With Video Codec (Save/Load AVI)");
            Console.WriteLine("------------------------------------------");

            try
            {
                var frames = CreateTestFrames(10, 320, 240);
                string message = "Test Message 123";
                string key = "TestKey";

                var stegoFrames = StegoCore.EmbedVideo(frames, message, key);
                Console.WriteLine("? Embedding successful");

                string tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "diagnostic_test.avi");
                Console.WriteLine($"Saving to: {tempPath}");
                VideoHelperFFmpeg.SaveLosslessAVI(tempPath, stegoFrames, 24);
                Console.WriteLine("? Save successful");

                var loadedFrames = VideoHelperFFmpeg.LoadFrames(tempPath);
                Console.WriteLine($"? Load successful");
                Console.WriteLine($"Frame count after load: {loadedFrames.Count}");

                Console.WriteLine("\nChecking LSB preservation...");
                int changedPixels = 0;
                int totalChecked = 0;

                for (int i = 0; i < Math.Min(stegoFrames.Count, loadedFrames.Count); i++)
                {
                    using (var origAccessor = new FastBitmapAccessor(stegoFrames[i]))
                    using (var loadedAccessor = new FastBitmapAccessor(loadedFrames[i]))
                    {
                        origAccessor.Lock();
                        loadedAccessor.Lock();

                        int width = Math.Min(origAccessor.Width, loadedAccessor.Width);
                        int height = Math.Min(origAccessor.Height, loadedAccessor.Height);

                        for (int y = 0; y < height && totalChecked < 1000; y++)
                        {
                            for (int x = 0; x < width && totalChecked < 1000; x++)
                            {
                                byte origBlue = origAccessor.GetBlue(x, y);
                                byte loadedBlue = loadedAccessor.GetBlue(x, y);

                                if ((origBlue & 1) != (loadedBlue & 1))
                                {
                                    changedPixels++;
                                }

                                totalChecked++;
                            }
                        }
                    }
                }

                double corruptionRate = (double)changedPixels / totalChecked * 100.0;
                Console.WriteLine($"LSB corruption rate: {corruptionRate:F2}% ({changedPixels}/{totalChecked} pixels)");

                Console.WriteLine("\nAttempting extraction...");
                var result = StegoCore.ExtractVideo(loadedFrames, key);
                string extracted = result.Message;
                Console.WriteLine($"Extracted message: '{extracted}'");

                if (extracted == message)
                {
                    Console.WriteLine("? PASSED: Codec preserves LSBs well enough!");
                }
                else if (extracted.Contains("ERROR"))
                {
                    Console.WriteLine("? FAILED: Extraction error");
                    Console.WriteLine(" Root cause: Video codec corrupted LSB data");
                }
                else
                {
                    Console.WriteLine($"? FAILED: Message mismatch or hash error");
                }

                try { System.IO.File.Delete(tempPath); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
                Console.WriteLine($" Stack: {ex.StackTrace}");
            }

            Console.WriteLine();
        }

        static void Test_BitCorruption()
        {
            Console.WriteLine("Test 3: Detailed Bit Corruption Analysis");
            Console.WriteLine("------------------------------------------");

            try
            {
                var frame = new GdiBitmap(100, 100);

                using (var accessor = new FastBitmapAccessor(frame))
                {
                    accessor.Lock();
                    for (int y = 0; y < 100; y++)
                    {
                        for (int x = 0; x < 100; x++)
                        {
                            byte blue = (byte)((x + y) % 2 == 0 ? 100 : 101);
                            accessor.SetBlue(x, y, blue);
                        }
                    }
                    accessor.Unlock();
                }

                var frames = new List<GdiBitmap> { frame };
                string tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "lsb_test.avi");

                VideoHelperFFmpeg.SaveLosslessAVI(tempPath, frames, 24);
                var loadedFrames = VideoHelperFFmpeg.LoadFrames(tempPath);

                int corrupted = 0;
                int total = 0;

                using (var origAccessor = new FastBitmapAccessor(frame))
                using (var loadedAccessor = new FastBitmapAccessor(loadedFrames[0]))
                {
                    origAccessor.Lock();
                    loadedAccessor.Lock();

                    for (int y = 0; y < 100; y++)
                    {
                        for (int x = 0; x < 100; x++)
                        {
                            byte origBlue = origAccessor.GetBlue(x, y);
                            byte loadedBlue = loadedAccessor.GetBlue(x, y);

                            if ((origBlue & 1) != (loadedBlue & 1))
                            {
                                corrupted++;
                            }
                            total++;
                        }
                    }
                }

                double rate = (double)corrupted / total * 100.0;
                Console.WriteLine($"LSB corruption: {rate:F2}% ({corrupted}/{total})");

                if (rate > 5.0)
                {
                    Console.WriteLine("? CRITICAL: Codec destroys LSB data!");
                    Console.WriteLine(" Solution: Use lossless format (PNG, FFV1, etc.)");
                }
                else if (rate > 0.1)
                {
                    Console.WriteLine("? WARNING: Some LSB corruption detected");
                }
                else
                {
                    Console.WriteLine("? LSBs preserved well");
                }

                try { System.IO.File.Delete(tempPath); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
            }

            Console.WriteLine();
        }

        static List<GdiBitmap> CreateTestFrames(int count, int width, int height)
        {
            var frames = new List<GdiBitmap>();
            var rnd = new Random(42);

            for (int i = 0; i < count; i++)
            {
                var bitmap = new GdiBitmap(width, height);
                using (var accessor = new FastBitmapAccessor(bitmap))
                {
                    accessor.Lock();
                    for (int y = 0; y < height; y++)
                    {
                        for (int x = 0; x < width; x++)
                        {
                            byte r = (byte)rnd.Next(256);
                            byte g = (byte)rnd.Next(256);
                            byte b = (byte)rnd.Next(256);
                            accessor.SetPixel(x, y, Color.FromArgb(r, g, b));
                        }
                    }
                    accessor.Unlock();
                }
                frames.Add(bitmap);
            }

            return frames;
        }
    }
}
