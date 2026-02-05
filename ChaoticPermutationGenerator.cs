using System;
using System.Security.Cryptography;
using System.Text;

namespace VidStegX.Models
{
    /// <summary>
    /// Generates deterministic values using chaotic logistic map.
    /// Lightweight version - does not allocate large arrays.
    /// </summary>
    public static class ChaoticPermutationGenerator
    {
        /// <summary>
        /// Generates a deterministic seed from a key.
        /// </summary>
        public static int GetSeed(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be empty");

            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(key));

            int seed = 0;
            for (int i = 0; i < hash.Length; i += 4)
            {
                int chunk = BitConverter.ToInt32(hash, i);
                seed ^= chunk;        // XOR combine, no encryption of message
            }

            return seed;
        }


        /// <summary>
        /// Gets chaotic value at specific index for given key.
        /// Uses logistic map: x(n+1) = r * x(n) * (1 - x(n))
        /// </summary>
        public static double GetChaoticValue(string key, int index)
        {
            int seed = Math.Abs(GetSeed(key));
            double x = ((seed % 9999) + 1) / 10000.0;
            const double r = 3.99;

            for (int i = 0; i <= index; i++)
            {
                x = r * x * (1 - x);
            }

            return x;
        }

        /// <summary>
        /// Generates a permuted index for a given position.
        /// Note: This is computationally expensive for large indices.
        /// For sequential access, use ChaoticSequence class instead.
        /// </summary>
        public static int GetPermutedIndex(int position, int totalLength, string key)
        {
            double chaoticValue = GetChaoticValue(key, position);
            return (int)(chaoticValue * totalLength) % totalLength;
        }
    }

    /// <summary>
    /// Streaming chaotic sequence generator - memory efficient.
    /// </summary>
    public class ChaoticSequence
    {
        private double _x;
        private readonly double _initialX;
        private const double R = 3.99;

        public ChaoticSequence(string key)
        {
            int seed = Math.Abs(ChaoticPermutationGenerator.GetSeed(key));
            _initialX = ((seed % 9999) + 1) / 10000.0;
            _x = _initialX;
        }

        public void Reset()
        {
            _x = _initialX;
        }

        public double Next()
        {
            _x = R * _x * (1 - _x);
            return _x;
        }

        public int NextIndex(int maxValue)
        {
            return (int)(Next() * maxValue) % maxValue;
        }
    }
}
