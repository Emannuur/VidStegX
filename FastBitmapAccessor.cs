using System;
using System.Drawing;
using System.Drawing.Imaging;

namespace VidStegX.Models
{
    /// <summary>
    /// Fast bitmap pixel access using LockBits and a managed buffer.
    /// Works with 24bpp RGB and handles positive/negative stride correctly.
    /// </summary>
    public sealed class FastBitmapAccessor : IDisposable
    {
        private readonly Bitmap _bitmap;
        private BitmapData? _bitmapData;
        private readonly int _width;
        private readonly int _height;
        private int _stride;
        private byte[]? _pixelData;
        private bool _locked;

        public int Width => _width;
        public int Height => _height;

        public FastBitmapAccessor(Bitmap bitmap)
        {
            _bitmap = bitmap ?? throw new ArgumentNullException(nameof(bitmap));
            if (_bitmap.PixelFormat != PixelFormat.Format24bppRgb)
                throw new ArgumentException("Bitmap must be Format24bppRgb.", nameof(bitmap));

            _width = _bitmap.Width;
            _height = _bitmap.Height;
        }

        public void Lock()
        {
            if (_locked) return;

            var rect = new Rectangle(0, 0, _width, _height);
            _bitmapData = _bitmap.LockBits(rect, ImageLockMode.ReadWrite, PixelFormat.Format24bppRgb);
            _stride = _bitmapData.Stride;               // may be negative
            int dataSize = Math.Abs(_stride) * _height; // always >= needed bytes
            _pixelData = new byte[dataSize];

            unsafe
            {
                byte* src = (byte*)_bitmapData.Scan0;
                for (int i = 0; i < dataSize; i++)
                    _pixelData[i] = src[i];
            }

            _locked = true;
        }

        public void Unlock()
        {
            if (!_locked || _bitmapData == null || _pixelData == null)
                return;

            int dataSize = _pixelData.Length;

            unsafe
            {
                byte* dst = (byte*)_bitmapData.Scan0;
                for (int i = 0; i < dataSize; i++)
                    dst[i] = _pixelData[i];
            }

            _bitmap.UnlockBits(_bitmapData);
            _bitmapData = null;
            _pixelData = null;
            _locked = false;
        }

        private void EnsureLocked()
        {
            if (!_locked || _pixelData == null)
                throw new InvalidOperationException("Bitmap must be locked before accessing pixels.");
        }

        private void CheckBounds(int x, int y)
        {
            if (x < 0 || x >= _width || y < 0 || y >= _height)
                throw new ArgumentOutOfRangeException("Coordinates out of bounds.");
        }

        private int Index(int x, int y)
        {
            // handle positive or negative stride
            int rowStart = (_stride > 0)
                ? y * _stride
                : (_height - 1 - y) * Math.Abs(_stride);
            return rowStart + x * 3; // BGR
        }

        public byte GetBlue(int x, int y)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y);
            return _pixelData![i];
        }

        public void SetBlue(int x, int y, byte value)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y);
            _pixelData![i] = value;
        }

        public byte GetGreen(int x, int y)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y) + 1;
            return _pixelData![i];
        }

        public void SetGreen(int x, int y, byte value)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y) + 1;
            _pixelData![i] = value;
        }

        public byte GetRed(int x, int y)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y) + 2;
            return _pixelData![i];
        }

        public void SetRed(int x, int y, byte value)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y) + 2;
            _pixelData![i] = value;
        }

        public Color GetPixel(int x, int y)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y);
            byte b = _pixelData![i];
            byte g = _pixelData[i + 1];
            byte r = _pixelData[i + 2];
            return Color.FromArgb(r, g, b);
        }

        public void SetPixel(int x, int y, Color color)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y);
            _pixelData![i] = color.B;
            _pixelData[i + 1] = color.G;
            _pixelData[i + 2] = color.R;
        }

        public void SetGray(int x, int y, byte value)
        {
            EnsureLocked(); CheckBounds(x, y);
            int i = Index(x, y);
            _pixelData![i] = value;
            _pixelData[i + 1] = value;
            _pixelData[i + 2] = value;
        }

        public void Dispose()
        {
            Unlock();
        }
    }
}
