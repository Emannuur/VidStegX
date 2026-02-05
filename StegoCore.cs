using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace VidStegX.Models
{
    /// <summary>
    /// Reversible Video Steganography Core
    /// 1. Reversibility → Side-info (original LSBs) store + restore
    /// 2. Same logic for embed & extract → Same chaotic sequence pattern
    /// 3. Randomization with chaotic logistic map + XOR seed → ChaoticSequence / ChaoticPermutationGenerator
    /// </summary>
    public static class StegoCore
    {
        // ==================== RESULT TYPE ====================
        public readonly struct ExtractionResult
        {
            public string Message { get; }
            public bool HashValid { get; }
            public bool HasError { get; }
            public string Error { get; }

            public ExtractionResult(
                string message,
                bool hashValid,
                bool hasError,
                string error)
            {
                Message = message;
                HashValid = hashValid;
                HasError = hasError;
                Error = error;
            }
        }

        // ==================== EMBED ====================
        public static List<Bitmap> EmbedVideo(
            List<Bitmap> frames,
            string message,
            string key,
            Action<int, Bitmap?>? progress = null)
        {
            if (frames == null || frames.Count == 0)
                throw new ArgumentException("Frames list is empty.");
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key is required.");
            if (string.IsNullOrWhiteSpace(message))
                throw new ArgumentException("Message cannot be empty.");

            // Original frames ko safe rakhne ke liye clone
            var workingFrames = CloneFrames(frames);

            // Payload: [4 bytes length][message][32-byte SHA256 hash]
            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            byte[] hash;
            using (var sha = SHA256.Create())
                hash = sha.ComputeHash(msgBytes);

            int payloadBytes = 4 + msgBytes.Length + 32;
            byte[] payload = new byte[payloadBytes];

            BitConverter.GetBytes(msgBytes.Length).CopyTo(payload, 0);
            msgBytes.CopyTo(payload, 4);
            hash.CopyTo(payload, 4 + msgBytes.Length);

            int width = workingFrames[0].Width;
            int height = workingFrames[0].Height;
            int pixelsPerFrame = width * height;
            int totalPixels = workingFrames.Count * pixelsPerFrame;

            int B = payloadBytes * 8;   // bits for payload
            int requiredPixels = 2 * B; // payload + side-info

            if (requiredPixels > totalPixels)
                throw new ArgumentException(
                    $"Message too large for reversible embedding. Need {requiredPixels} pixels, have {totalPixels}");

            System.Diagnostics.Debug.WriteLine(
                $"EMBED: width={width}, height={height}, frames={workingFrames.Count}, " +
                $"payloadBytes={payloadBytes}, B={B}, requiredPixels={requiredPixels}, totalPixels={totalPixels}");

            // Chaotic logistic sequence with XOR-based seed
            var chaotic = new ChaoticSequence(key);

            // Side-info buffer for original LSBs
            bool[] originalLsbs = new bool[B];

            // -------- PHASE 1: payload bits embed + original LSB store --------
            int bitIndex = 0;
            for (int frameIdx = 0; frameIdx < workingFrames.Count && bitIndex < B; frameIdx++)
            {
                var frame = workingFrames[frameIdx];
                using var accessor = new FastBitmapAccessor(frame);
                accessor.Lock();

                for (int localPixel = 0; localPixel < pixelsPerFrame && bitIndex < B; localPixel++)
                {
                    int globalPixelIndex = chaotic.NextIndex(totalPixels);
                    int fIdx = globalPixelIndex / pixelsPerFrame;
                    if (fIdx != frameIdx) continue;

                    int pixelInFrame = globalPixelIndex % pixelsPerFrame;
                    int y = pixelInFrame / width;
                    int x = pixelInFrame % width;

                    byte blue = accessor.GetBlue(x, y);

                    // save original LSB
                    originalLsbs[bitIndex] = (blue & 1) == 1;

                    // payload bit
                    int byteIdx = bitIndex / 8;
                    int bitInByte = 7 - (bitIndex % 8);
                    int bit = (payload[byteIdx] >> bitInByte) & 1;

                    byte newBlue = (byte)((blue & 0xFE) | bit);
                    accessor.SetBlue(x, y, newBlue);

                    bitIndex++;
                }

                accessor.Unlock();

                int percent = (int)((frameIdx + 1) * 50.0 / workingFrames.Count);
                progress?.Invoke(percent, frame);
            }

            // -------- PHASE 2: side-info (original LSBs) embed --------
            int sideIndex = 0;
            for (int frameIdx = 0; frameIdx < workingFrames.Count && sideIndex < B; frameIdx++)
            {
                var frame = workingFrames[frameIdx];
                using var accessor = new FastBitmapAccessor(frame);
                accessor.Lock();

                for (int localPixel = 0; localPixel < pixelsPerFrame && sideIndex < B; localPixel++)
                {
                    int globalPixelIndex = chaotic.NextIndex(totalPixels); // same sequence continue
                    int fIdx = globalPixelIndex / pixelsPerFrame;
                    if (fIdx != frameIdx) continue;

                    int pixelInFrame = globalPixelIndex % pixelsPerFrame;
                    int y = pixelInFrame / width;
                    int x = pixelInFrame % width;

                    byte blue = accessor.GetBlue(x, y);
                    int bit = originalLsbs[sideIndex] ? 1 : 0;

                    byte newBlue = (byte)((blue & 0xFE) | bit);
                    accessor.SetBlue(x, y, newBlue);

                    sideIndex++;
                }

                accessor.Unlock();

                int percent = 50 + (int)((frameIdx + 1) * 50.0 / workingFrames.Count);
                if (percent > 100) percent = 100;
                progress?.Invoke(percent, frame);
            }

            return workingFrames; // stego frames
        }

        // ==================== EXTRACT (mirror of embed) ====================
        public static ExtractionResult ExtractVideo(
            List<Bitmap> frames,
            string key,
            Action<string?>? updateCallback = null,
            Action<int, Bitmap?>? progress = null)
        {
            if (frames == null || frames.Count == 0)
            {
                const string err = "[ERROR: No frames provided]";
                updateCallback?.Invoke(err);
                return new ExtractionResult(string.Empty, false, true, err);
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                const string err = "[ERROR: Key is required]";
                updateCallback?.Invoke(err);
                return new ExtractionResult(string.Empty, false, true, err);
            }

            // Clone for safe reading
            var workingFrames = CloneFrames(frames);

            try
            {
                int width = workingFrames[0].Width;
                int height = workingFrames[0].Height;
                int pixelsPerFrame = width * height;
                int totalPixels = workingFrames.Count * pixelsPerFrame;

                // ================== PHASE 0: sirf length (4 bytes / 32 bits) ==================
                var seq = new ChaoticSequence(key);

                byte[] lenBuf = new byte[4];
                ReadBitsChaotic(workingFrames, seq, lenBuf, 0, 32, width, height);
                int msgLen = BitConverter.ToInt32(lenBuf, 0);

                if (msgLen <= 0 || msgLen > 1_000_000)
                {
                    string err = $"[ERROR: Invalid message length ({msgLen}). Wrong key or no hidden message.]";
                    updateCallback?.Invoke(err);
                    return new ExtractionResult(string.Empty, false, true, err);
                }

                // payload: [4 bytes length][message][32-byte hash]
                int payloadBytes = 4 + msgLen + 32;
                int B = payloadBytes * 8;          // total payload bits
                int requiredPixels = 2 * B;        // payload + side-info

                if (requiredPixels > totalPixels)
                {
                    const string err = "[ERROR: Claimed message larger than video capacity for reversible mode]";
                    updateCallback?.Invoke(err);
                    return new ExtractionResult(string.Empty, false, true, err);
                }

                System.Diagnostics.Debug.WriteLine(
                    $"EXTRACT: width={width}, height={height}, frames={workingFrames.Count}, " +
                    $"msgLen={msgLen}, payloadBytes={payloadBytes}, B={B}, requiredPixels={requiredPixels}, totalPixels={totalPixels}");

                // ================== PHASE 1: exact payload dobara read ==================
                // sequence ko reset karo, taake embed ke pattern se match ho
                seq = new ChaoticSequence(key);

                byte[] payload = new byte[payloadBytes];
                ReadBitsChaotic(workingFrames, seq, payload, 0, B, width, height);

                // ================== PHASE 2: side‑info (original LSBs) read ==================
                bool[] originalLsbs = new bool[B];
                ReadSideInfoChaotic(workingFrames, seq, originalLsbs, B, width, height);

                // ================== Message + hash verify ==================
                byte[] messageBytes = new byte[msgLen];
                byte[] embeddedHash = new byte[32];

                Buffer.BlockCopy(payload, 4, messageBytes, 0, msgLen);
                Buffer.BlockCopy(payload, 4 + msgLen, embeddedHash, 0, 32);

                byte[] calcHash;
                using (var sha = SHA256.Create())
                    calcHash = sha.ComputeHash(messageBytes);

                bool hashValid = true;
                for (int i = 0; i < 32; i++)
                {
                    if (embeddedHash[i] != calcHash[i])
                    {
                        hashValid = false;
                        break;
                    }
                }

                string extractedMessage = Encoding.UTF8.GetString(messageBytes);

                // ================== Original video restore ==================
                // yahan original frames list par hi restore kar rahe hain
                RestoreOriginalLsbs(frames, key, originalLsbs, B, progress);

                if (!hashValid)
                {
                    const string err = "[ERROR: HASH MISMATCH - Wrong key or corrupted data]";
                    updateCallback?.Invoke(err);
                    return new ExtractionResult(string.Empty, false, true, err);
                }

                updateCallback?.Invoke(extractedMessage);
                return new ExtractionResult(extractedMessage, true, false, string.Empty);
            }
            catch (Exception ex)
            {
                string err = $"[EXTRACTION ERROR: {ex.Message}]";
                updateCallback?.Invoke(err);
                return new ExtractionResult(string.Empty, false, true, err);
            }
        }

        // ==================== HELPERS ====================

        private static List<Bitmap> CloneFrames(List<Bitmap> frames)
        {
            var list = new List<Bitmap>(frames.Count);
            foreach (var f in frames)
                list.Add((Bitmap)f.Clone());
            return list;
        }

        private static void ReadBitsChaotic(
            List<Bitmap> frames,
            ChaoticSequence seq,
            byte[] output,
            int startBit,
            int bitCount,
            int width,
            int height)
        {
            int pixelsPerFrame = width * height;
            int totalPixels = frames.Count * pixelsPerFrame;

            int startByte = startBit / 8;
            int endByte = (startBit + bitCount + 7) / 8;
            for (int i = startByte; i < endByte && i < output.Length; i++)
                output[i] = 0;

            int bitsRead = 0;
            for (int frameIdx = 0; frameIdx < frames.Count && bitsRead < bitCount; frameIdx++)
            {
                var frame = frames[frameIdx];
                using var accessor = new FastBitmapAccessor(frame);
                accessor.Lock();

                for (int localPixel = 0; localPixel < pixelsPerFrame && bitsRead < bitCount; localPixel++)
                {
                    int globalPixelIndex = seq.NextIndex(totalPixels);
                    int fIdx = globalPixelIndex / pixelsPerFrame;
                    if (fIdx != frameIdx) continue;

                    int pixelInFrame = globalPixelIndex % pixelsPerFrame;
                    int y = pixelInFrame / width;
                    int x = pixelInFrame % width;

                    byte blue = accessor.GetBlue(x, y);
                    int bit = blue & 1;

                    int outBitIndex = startBit + bitsRead;
                    int outByteIdx = outBitIndex / 8;
                    int outBitInByte = 7 - (outBitIndex % 8);

                    if (outByteIdx >= 0 && outByteIdx < output.Length && bit == 1)
                        output[outByteIdx] |= (byte)(1 << outBitInByte);

                    bitsRead++;
                }

                accessor.Unlock();
            }
        }

        private static void ReadSideInfoChaotic(
            List<Bitmap> frames,
            ChaoticSequence seq,
            bool[] origLsbs,
            int B,
            int width,
            int height)
        {
            int pixelsPerFrame = width * height;
            int totalPixels = frames.Count * pixelsPerFrame;

            int bitsRead = 0;
            for (int frameIdx = 0; frameIdx < frames.Count && bitsRead < B; frameIdx++)
            {
                var frame = frames[frameIdx];
                using var accessor = new FastBitmapAccessor(frame);
                accessor.Lock();

                for (int localPixel = 0; localPixel < pixelsPerFrame && bitsRead < B; localPixel++)
                {
                    int globalPixelIndex = seq.NextIndex(totalPixels);
                    int fIdx = globalPixelIndex / pixelsPerFrame;
                    if (fIdx != frameIdx) continue;

                    int pixelInFrame = globalPixelIndex % pixelsPerFrame;
                    int y = pixelInFrame / width;
                    int x = pixelInFrame % width;

                    byte blue = accessor.GetBlue(x, y);
                    origLsbs[bitsRead] = (blue & 1) == 1;

                    bitsRead++;
                }

                accessor.Unlock();
            }
        }

        private static void RestoreOriginalLsbs(
            List<Bitmap> frames,
            string key,
            bool[] originalLsbs,
            int B,
            Action<int, Bitmap?>? progress = null)
        {
            int width = frames[0].Width;
            int height = frames[0].Height;
            int pixelsPerFrame = width * height;
            int totalPixels = frames.Count * pixelsPerFrame;

            var seq = new ChaoticSequence(key);
            int idx = 0;

            for (int frameIdx = 0; frameIdx < frames.Count && idx < B; frameIdx++)
            {
                var frame = frames[frameIdx];
                using var accessor = new FastBitmapAccessor(frame);
                accessor.Lock();

                for (int localPixel = 0; localPixel < pixelsPerFrame && idx < B; localPixel++)
                {
                    int globalPixelIndex = seq.NextIndex(totalPixels);
                    int fIdx = globalPixelIndex / pixelsPerFrame;
                    if (fIdx != frameIdx) continue;

                    int pixelInFrame = globalPixelIndex % pixelsPerFrame;
                    int y = pixelInFrame / width;
                    int x = pixelInFrame % width;

                    byte blue = accessor.GetBlue(x, y);
                    int bit = originalLsbs[idx] ? 1 : 0;

                    byte newB = (byte)((blue & 0xFE) | bit);
                    accessor.SetBlue(x, y, newB);

                    idx++;
                }

                accessor.Unlock();

                int percent = (int)((frameIdx + 1) * 100.0 / frames.Count);

                // UI ke liye safe clone, taake "object is in use elsewhere" na aaye
                Bitmap? previewClone = null;
                try
                {
                    previewClone = (Bitmap)frame.Clone();
                }
                catch
                {
                    // ignore clone error
                }

                progress?.Invoke(percent, previewClone);
                previewClone?.Dispose();
            }
        }

        // ==================== PSNR ====================
        public static double ComputeFramePSNR(Bitmap original, Bitmap stego)
        {
            if (original == null || stego == null)
                throw new ArgumentNullException();
            if (original.Width != stego.Width || original.Height != stego.Height)
                throw new ArgumentException("Frame sizes must match.");

            double mse = 0.0;
            int width = original.Width;
            int height = original.Height;
            long count = 0;

            using var a1 = new FastBitmapAccessor(original);
            using var a2 = new FastBitmapAccessor(stego);
            a1.Lock();
            a2.Lock();

            for (int y = 0; y < height; y++)
            {
                for (int x = 0; x < width; x++)
                {
                    byte b1 = a1.GetBlue(x, y);
                    byte g1 = a1.GetGreen(x, y);
                    byte r1 = a1.GetRed(x, y);

                    byte b2 = a2.GetBlue(x, y);
                    byte g2 = a2.GetGreen(x, y);
                    byte r2 = a2.GetRed(x, y);

                    int dr = r1 - r2;
                    int dg = g1 - g2;
                    int db = b1 - b2;

                    mse += dr * dr + dg * dg + db * db;
                    count += 3;
                }
            }

            a1.Unlock();
            a2.Unlock();

            if (count == 0) return 0.0;
            mse /= count;
            if (mse == 0) return 99.0;

            double maxI = 255.0;
            return 10.0 * Math.Log10((maxI * maxI) / mse);
        }
    }
}
