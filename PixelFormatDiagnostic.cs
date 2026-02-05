using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using VidStegX.Models;

namespace VidStegX.Tests
{
    using GdiBitmap = System.Drawing.Bitmap;

    public static class PixelFormatDiagnostic
    {
        public static void RunTest()
        {
            Console.WriteLine("=== PIXEL FORMAT DIAGNOSTIC TEST ===");
            Console.WriteLine();
            try
            {
                int width = 100;
                int height = 100;
                var testBitmap = new GdiBitmap(width, height);
                Console.WriteLine("Step 1: Creating test pattern with known LSBs...");

                using (var accessor = new FastBitmapAccessor(testBitmap))
                {
                    accessor.Lock();
                    for (int y = 0; y < height; y++)
                    {
                        for (int x = 0; x < width; x++)
                        {
                            byte blueValue = (byte)((x + y) % 2 == 0 ? 100 : 101);
                            accessor.SetPixel(x, y, Color.FromArgb(200, 128, blueValue));
                        }
                    }
                    accessor.Unlock();
                }
                Console.WriteLine(" ? Test pattern created");
                Console.WriteLine($" Blue values: 100 (LSB=0) and 101 (LSB=1)");

                string testOutput = Path.Combine(Path.GetTempPath(), "pixel_test.avi");
                Console.WriteLine();
                Console.WriteLine("Step 2: Encoding with FFV1 (bgr24)...");

                var frames = new List<GdiBitmap> { testBitmap };
                VideoHelperFFmpeg.SaveLosslessAVI(testOutput, frames, 24);

                Console.WriteLine($" ? Encoded to: {testOutput}");

                Console.WriteLine();
                Console.WriteLine("Step 3: Decoding video...");
                var loadedFrames = VideoHelperFFmpeg.LoadFrames(testOutput);

                if (loadedFrames.Count == 0)
                {
                    Console.WriteLine(" ? FAILED: No frames loaded!");
                    return;
                }
                Console.WriteLine($" ? Loaded {loadedFrames.Count} frame(s)");

                Console.WriteLine();
                Console.WriteLine("Step 4: Verifying LSB preservation...");

                var loadedBitmap = loadedFrames[0];
                int errors = 0;
                int total = 0;
                using (var accessor = new FastBitmapAccessor(loadedBitmap))
                {
                    accessor.Lock();
                    for (int y = 0; y < Math.Min(height, loadedBitmap.Height); y++)
                    {
                        for (int x = 0; x < Math.Min(width, loadedBitmap.Width); x++)
                        {
                            byte originalBlue = (byte)((x + y) % 2 == 0 ? 100 : 101);
                            byte loadedBlue = accessor.GetBlue(x, y);

                            int originalLSB = originalBlue & 1;
                            int loadedLSB = loadedBlue & 1;
                            total++;

                            if (originalLSB != loadedLSB)
                            {
                                errors++;
                                if (errors <= 10)
                                {
                                    Console.WriteLine($" ? Pixel ({x},{y}): Original={originalBlue} (LSB={originalLSB}), Loaded={loadedBlue} (LSB={loadedLSB})");
                                }
                            }
                        }
                    }
                    accessor.Unlock();
                }

                Console.WriteLine();
                Console.WriteLine("=== RESULTS ===");
                Console.WriteLine($"Total pixels tested: {total}");
                Console.WriteLine($"LSB errors: {errors}");
                Console.WriteLine($"LSB preservation: {((total - errors) * 100.0 / total):F2}%");
                Console.WriteLine();
                if (errors == 0)
                {
                    Console.WriteLine("? SUCCESS! 100% LSB preservation");
                    Console.WriteLine(" ? FFV1 encoding/decoding is PERFECT");
                    Console.WriteLine(" ? Steganography will work correctly");
                }
                else
                {
                    Console.WriteLine("? FAILURE! LSBs are being corrupted");
                    Console.WriteLine(" ? Problem is in encode/decode pipeline");
                }

                try
                {
                    File.Delete(testOutput);
                    testBitmap.Dispose();
                    foreach (var frame in loadedFrames) frame.Dispose();
                }
                catch { }

                Console.WriteLine();
                Console.WriteLine("=== END DIAGNOSTIC ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? TEST FAILED WITH EXCEPTION: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }
    }
}