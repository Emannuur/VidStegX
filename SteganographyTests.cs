using System;
using System.Collections.Generic;
using System.Drawing;
using VidStegX.Models;
namespace VidStegX.Tests
{
    using System;
    using System.Collections.Generic;
    using VidStegX.Models;
    using GdiBitmap = System.Drawing.Bitmap;
    public static class SteganographyTests
    {
        public static void RunAllTests()
        {
            Console.WriteLine("=== STEGANOGRAPHY IMPLEMENTATION TESTS ===\n");
            Test1_ChaoticSequence();
            Test2_FastBitmapAccessor();
            Test3_BasicEmbedExtract();
            Test4_LargeMessage();
            Test5_WrongKey();
            Test6_Capacity();
            Console.WriteLine("\n=== ALL TESTS COMPLETE ===");
        }
        static void Test1_ChaoticSequence()
        {
            Console.WriteLine("Test 1: Chaotic Sequence Generator");
            Console.WriteLine("-----------------------------------");
            try
            {
                string key = "TestKey123";
                var seq1 = new ChaoticSequence(key);
                var seq2 = new ChaoticSequence(key);
                bool deterministic = true;
                for (int i = 0; i < 100; i++)
                {
                    double v1 = seq1.Next();
                    double v2 = seq2.Next();
                    if (Math.Abs(v1 - v2) > 0.0001)
                    {
                        deterministic = false;
                        break;
                    }
                }
                if (!deterministic)
                {
                    Console.WriteLine("? FAILED: Not deterministic");
                    return;
                }
                seq1.Reset();
                var seq3 = new ChaoticSequence(key);
                bool resetWorks = Math.Abs(seq1.Next() - seq3.Next()) < 0.0001;
                if (!resetWorks)
                {
                    Console.WriteLine("? FAILED: Reset not working");
                    return;
                }
                Console.WriteLine("? PASSED: Deterministic and reset works");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
            }
            Console.WriteLine();
        }
        static void Test2_FastBitmapAccessor()
        {
            Console.WriteLine("Test 2: Fast Bitmap Accessor");
            Console.WriteLine("-----------------------------");
            try
            {
                var bitmap = new GdiBitmap(100, 100);
                using (var accessor = new FastBitmapAccessor(bitmap))
                {
                    accessor.Lock();
                    accessor.SetBlue(10, 20, 123);
                    accessor.SetBlue(50, 50, 200);
                    byte blue1 = accessor.GetBlue(10, 20);
                    byte blue2 = accessor.GetBlue(50, 50);
                    accessor.Unlock();
                    if (blue1 != 123 || blue2 != 200)
                    {
                        Console.WriteLine($"? FAILED: Read/write mismatch ({blue1}, {blue2})");
                        return;
                    }
                }
                Console.WriteLine("? PASSED: Read/write operations correct");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
            }
            Console.WriteLine();
        }
        static void Test3_BasicEmbedExtract()
        {
            Console.WriteLine("Test 3: Basic Embed & Extract");
            Console.WriteLine("------------------------------");
            try
            {
                var frames = CreateTestFrames(10, 320, 240);
                string originalMessage = "Hello, World! This is a test message.";
                string key = "SecretKey123";
                var stegoFrames = StegoCore.EmbedVideo(frames, originalMessage, key);
                var result = StegoCore.ExtractVideo(stegoFrames, key);
                string extractedMessage = result.Message;
                if (extractedMessage.Contains("HASH MISMATCH") || extractedMessage.Contains("ERROR"))
                {
                    Console.WriteLine($"? FAILED: {extractedMessage}");
                    return;
                }
                if (extractedMessage != originalMessage)
                {
                    Console.WriteLine($"? FAILED: Message mismatch");
                    Console.WriteLine($" Expected: {originalMessage}");
                    Console.WriteLine($" Got: {extractedMessage}");
                    return;
                }
                Console.WriteLine("? PASSED: Message embedded and extracted correctly");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
            }
            Console.WriteLine();
        }
        static void Test4_LargeMessage()
        {
            Console.WriteLine("Test 4: Large Message");
            Console.WriteLine("----------------------");
            try
            {
                var frames = CreateTestFrames(50, 640, 480);
                string largeMessage = new string('A', 1024);
                string key = "LargeTestKey";
                var stegoFrames = StegoCore.EmbedVideo(frames, largeMessage, key);
                var result = StegoCore.ExtractVideo(stegoFrames, key);
                string extractedMessage = result.Message;
                if (extractedMessage.Contains("HASH MISMATCH") || extractedMessage.Contains("ERROR"))
                {
                    Console.WriteLine($"? FAILED: {extractedMessage}");
                    return;
                }
                if (extractedMessage != largeMessage)
                {
                    Console.WriteLine("? FAILED: Large message mismatch");
                    return;
                }
                Console.WriteLine("? PASSED: Large message handled correctly");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
            }
            Console.WriteLine();
        }
        static void Test5_WrongKey()
        {
            Console.WriteLine("Test 5: Wrong Key Detection");
            Console.WriteLine("----------------------------");
            try
            {
                var frames = CreateTestFrames(10, 320, 240);
                string message = "Secret message";
                string correctKey = "CorrectKey";
                string wrongKey = "WrongKey";
                var stegoFrames = StegoCore.EmbedVideo(frames, message, correctKey);
                var result = StegoCore.ExtractVideo(stegoFrames, wrongKey);
                string extracted = result.Message;
                if (!extracted.Contains("HASH MISMATCH") && !extracted.Contains("ERROR"))
                {
                    Console.WriteLine("? FAILED: Wrong key should produce error");
                    return;
                }
                Console.WriteLine("? PASSED: Wrong key detected correctly");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
            }
            Console.WriteLine();
        }
        static void Test6_Capacity()
        {
            Console.WriteLine("Test 6: Capacity Limits");
            Console.WriteLine("------------------------");
            try
            {
                var frames = CreateTestFrames(2, 100, 100);
                int totalPixels = 2 * 100 * 100;
                int maxBytes = (totalPixels / 8) - 4 - 32 - 10;
                string tooLarge = new string('X', totalPixels / 8 + 100);
                string key = "CapKey";
                try
                {
                    StegoCore.EmbedVideo(frames, tooLarge, key);
                    Console.WriteLine("? FAILED: Should reject message too large");
                    return;
                }
                catch (ArgumentException)
                {
                    // Expected
                }
                string fitsOk = new string('Y', Math.Max(10, maxBytes - 100));
                var okFrames = CreateTestFrames(2, 100, 100);
                okFrames = StegoCore.EmbedVideo(okFrames, fitsOk, key);
                var result = StegoCore.ExtractVideo(okFrames, key);
                string extracted = result.Message;
                if (extracted.Contains("ERROR"))
                {
                    Console.WriteLine($"? FAILED: Valid message failed: {extracted}");
                    return;
                }
                if (!extracted.StartsWith(fitsOk.Substring(0, Math.Min(10, fitsOk.Length))))
                {
                    Console.WriteLine("? FAILED: Extracted message doesn't match");
                    return;
                }
                Console.WriteLine("? PASSED: Capacity limits enforced correctly");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? FAILED: {ex.Message}");
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