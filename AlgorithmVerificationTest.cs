using System;
using System.Collections.Generic;
using System.Drawing;
using VidStegX.Models;

namespace VidStegX.Tests
{
    using GdiBitmap = System.Drawing.Bitmap;

    public static class AlgorithmVerificationTest
    {
        public static void RunTest()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("ALGORITHM VERIFICATION TEST");
            Console.WriteLine("Testing WITHOUT video codec (in-memory only)");
            Console.WriteLine("========================================\n");

            Test1_InMemoryEmbedExtract();
            Test2_MultipleMessages();
            Test3_LargeMessage();
            Test4_EdgeCases();

            Console.WriteLine("\n========================================");
            Console.WriteLine("ALGORITHM VERIFICATION COMPLETE");
            Console.WriteLine("========================================\n");
        }

        static void Test1_InMemoryEmbedExtract()
        {
            Console.WriteLine("Test 1: In-Memory Embed/Extract (No Codec)");
            Console.WriteLine("--------------------------------------------");

            try
            {
                var frames = CreateRandomFrames(10, 320, 240);

                string originalMessage = "Hello World! This is a test message.";
                string key = "TestKey123";

                Console.WriteLine($"Original message: '{originalMessage}'");
                Console.WriteLine($"Key: '{key}'");
                Console.WriteLine($"Frames: {frames.Count} frames of {frames[0].Width}x{frames[0].Height}");

                Console.WriteLine("\nEmbedding...");
                var stegoFrames = StegoCore.EmbedVideo(frames, originalMessage, key);
                Console.WriteLine("? Embedding complete");

                Console.WriteLine("\nExtracting...");
                var result = StegoCore.ExtractVideo(stegoFrames, key);
                string extractedMessage = result.Message;

                Console.WriteLine($"Extracted message: '{extractedMessage}'");

                bool matchesExact = extractedMessage == originalMessage;
                bool hasError = extractedMessage.Contains("[ERROR") || extractedMessage.Contains("[HASH MISMATCH]");

                if (matchesExact && !hasError)
                {
                    Console.WriteLine("\n? PASSED: Algorithm works perfectly!");
                    Console.WriteLine(" Conclusion: Problem is NOT the algorithm, it's the codec.");
                }
                else if (hasError)
                {
                    Console.WriteLine($"\n? FAILED: Algorithm has issues!");
                    Console.WriteLine($" Error: {extractedMessage}");
                    Console.WriteLine(" Conclusion: Algorithm itself is broken.");
                }
                else
                {
                    Console.WriteLine($"\n?? PARTIAL: Message extracted but modified");
                    Console.WriteLine($" Expected: '{originalMessage}'");
                    Console.WriteLine($" Got: '{extractedMessage}'");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n? EXCEPTION: {ex.Message}");
                Console.WriteLine($" Stack: {ex.StackTrace}");
            }

            Console.WriteLine();
        }

        static void Test2_MultipleMessages()
        {
            Console.WriteLine("Test 2: Multiple Messages (Different Keys)");
            Console.WriteLine("-------------------------------------------");

            try
            {
                var testCases = new[]
                {
                    ("Short", "Key1"),
                    ("Medium length message here", "Key2"),
                    ("A much longer message with more text to test capacity and algorithm robustness over multiple frames", "Key3")
                };

                int passed = 0;
                int failed = 0;

                foreach (var (message, key) in testCases)
                {
                    var testFrames = CreateRandomFrames(20, 400, 300);

                    var stegoFrames = StegoCore.EmbedVideo(testFrames, message, key);
                    var result = StegoCore.ExtractVideo(stegoFrames, key);
                    string extracted = result.Message;

                    if (extracted == message && !extracted.Contains("[ERROR") && !extracted.Contains("[HASH MISMATCH]"))
                    {
                        Console.WriteLine($"? PASS: '{message.Substring(0, Math.Min(20, message.Length))}...'");
                        passed++;
                    }
                    else
                    {
                        Console.WriteLine($"? FAIL: '{message.Substring(0, Math.Min(20, message.Length))}...'");
                        Console.WriteLine($" Expected: {message.Length} chars");
                        Console.WriteLine($" Got: {extracted}");
                        failed++;
                    }
                }

                Console.WriteLine($"\nResults: {passed}/{testCases.Length} passed");

                if (failed == 0)
                {
                    Console.WriteLine("? PASSED: All messages recovered correctly");
                }
                else
                {
                    Console.WriteLine($"? FAILED: {failed} messages failed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
            }

            Console.WriteLine();
        }

        static void Test3_LargeMessage()
        {
            Console.WriteLine("Test 3: Large Message (10KB)");
            Console.WriteLine("-----------------------------");

            try
            {
                var frames = CreateRandomFrames(100, 640, 480);

                string largeMessage = new string('A', 10 * 1024);
                string key = "LargeKey";

                Console.WriteLine($"Message size: {largeMessage.Length} bytes");
                Console.WriteLine($"Available capacity: {frames.Count * 640 * 480 / 8 - 36} bytes");

                var stegoFrames = StegoCore.EmbedVideo(frames, largeMessage, key);
                var result = StegoCore.ExtractVideo(stegoFrames, key);
                string extracted = result.Message;

                bool matches = extracted == largeMessage && !extracted.Contains("[ERROR");

                if (matches)
                {
                    Console.WriteLine("? PASSED: Large message recovered perfectly");
                }
                else
                {
                    Console.WriteLine($"? FAILED: Large message recovery failed");
                    Console.WriteLine($" Expected length: {largeMessage.Length}");
                    Console.WriteLine($" Got: {extracted.Substring(0, Math.Min(100, extracted.Length))}...");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
            }

            Console.WriteLine();
        }

        static void Test4_EdgeCases()
        {
            Console.WriteLine("Test 4: Edge Cases");
            Console.WriteLine("------------------");

            try
            {
                var frames1 = CreateRandomFrames(5, 320, 240);
                var stego1 = StegoCore.EmbedVideo(frames1, "X", "Key");
                var result1 = StegoCore.ExtractVideo(stego1, "Key");
                bool test1 = result1.Message == "X";
                Console.WriteLine($"Single char 'X': {(test1 ? "? PASS" : "? FAIL")}");

                var frames2 = CreateRandomFrames(10, 320, 240);
                string specialMsg = "Hello!@#$%^&*()_+-=[]{}|;:',.<>?/~`";
                var stego2 = StegoCore.EmbedVideo(frames2, specialMsg, "Key");
                var result2 = StegoCore.ExtractVideo(stego2, "Key");
                bool test2 = result2.Message == specialMsg;
                Console.WriteLine($"Special chars: {(test2 ? "? PASS" : "? FAIL")}");

                var frames3 = CreateRandomFrames(10, 320, 240);
                string unicodeMsg = "Hello ?? ????";
                var stego3 = StegoCore.EmbedVideo(frames3, unicodeMsg, "Key");
                var result3 = StegoCore.ExtractVideo(stego3, "Key");
                bool test3 = result3.Message == unicodeMsg;
                Console.WriteLine($"Unicode chars: {(test3 ? "? PASS" : "? FAIL")}");

                var frames4 = CreateRandomFrames(10, 320, 240);
                var stego4 = StegoCore.EmbedVideo(frames4, "Secret", "CorrectKey");
                var result4 = StegoCore.ExtractVideo(stego4, "WrongKey");
                bool test4 = result4.Message.Contains("[ERROR") || result4.Message.Contains("[HASH MISMATCH]");
                Console.WriteLine($"Wrong key detection: {(test4 ? "? PASS" : "? FAIL")}");

                int passCount = (test1 ? 1 : 0) + (test2 ? 1 : 0) + (test3 ? 1 : 0) + (test4 ? 1 : 0);

                if (passCount == 4)
                {
                    Console.WriteLine("\n? PASSED: All edge cases handled correctly");
                }
                else
                {
                    Console.WriteLine($"\n?? PARTIAL: {passCount}/4 edge cases passed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? EXCEPTION: {ex.Message}");
            }

            Console.WriteLine();
        }

        static List<GdiBitmap> CreateRandomFrames(int count, int width, int height)
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
