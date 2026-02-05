using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.ReactiveUI; // AvaloniaScheduler
using Avalonia.Threading;
using LiveChartsCore;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.Measure;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.Painting.Effects;
using ReactiveUI;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Reactive;
using System.Threading.Tasks;
using VidStegX.Models;
// aliases
using AvaloniaBitmap = Avalonia.Media.Imaging.Bitmap;
using GdiBitmap = System.Drawing.Bitmap;

namespace VidStegX.ViewModels
{
    public class MainWindowViewModel : ReactiveObject
    {
        // ---------- limits ----------
        private const int MaxMessageLength = 15;   // message max 15 chars
        private const int MinKeyLength = 4;
        private const int MaxKeyLength = 32;

        // ---------- Visibility ----------
        private bool _isMenuVisible = true;
        public bool IsMenuVisible { get => _isMenuVisible; set => this.RaiseAndSetIfChanged(ref _isMenuVisible, value); }

        private bool _isEmbedVisible;
        public bool IsEmbedVisible { get => _isEmbedVisible; set => this.RaiseAndSetIfChanged(ref _isEmbedVisible, value); }

        private bool _isExtractVisible;
        public bool IsExtractVisible { get => _isExtractVisible; set => this.RaiseAndSetIfChanged(ref _isExtractVisible, value); }

        private bool _isCompareVisible;
        public bool IsCompareVisible { get => _isCompareVisible; set => this.RaiseAndSetIfChanged(ref _isCompareVisible, value); }

        // ---------- Embed ----------
        private string _coverVideoPath = "";
        public string CoverVideoPath
        {
            get => _coverVideoPath;
            set
            {
                this.RaiseAndSetIfChanged(ref _coverVideoPath, value);
                this.RaisePropertyChanged(nameof(CanEmbed));
            }
        }

        private string _hiddenMessage = "";
        public string HiddenMessage
        {
            get => _hiddenMessage;
            set
            {
                if (!string.IsNullOrEmpty(value) && value.Length > MaxMessageLength)
                    value = value.Substring(0, MaxMessageLength);
                this.RaiseAndSetIfChanged(ref _hiddenMessage, value);
                this.RaisePropertyChanged(nameof(CanEmbed));
            }
        }

        private string _encryptionKey = "";
        public string EncryptionKey
        {
            get => _encryptionKey;
            set
            {
                if (!string.IsNullOrEmpty(value) && value.Length > MaxKeyLength)
                    value = value.Substring(0, MaxKeyLength);
                this.RaiseAndSetIfChanged(ref _encryptionKey, value);
                this.RaisePropertyChanged(nameof(CanEmbed));
            }
        }

        // ---------- Extract ----------
        private string _videoPath = "";
        public string VideoPath
        {
            get => _videoPath;
            set
            {
                this.RaiseAndSetIfChanged(ref _videoPath, value);
                this.RaisePropertyChanged(nameof(CanExtract));
            }
        }

        private string _secretKey = "";
        public string SecretKey
        {
            get => _secretKey;
            set
            {
                if (!string.IsNullOrEmpty(value) && value.Length > MaxKeyLength)
                    value = value.Substring(0, MaxKeyLength);
                this.RaiseAndSetIfChanged(ref _secretKey, value);
                this.RaisePropertyChanged(nameof(CanExtract));
            }
        }

        private string _extractedMessage = "";
        public string ExtractedMessage
        {
            get => _extractedMessage;
            set => this.RaiseAndSetIfChanged(ref _extractedMessage, value);
        }

        // ---------- Compare ----------
        private string _video1Path = "";
        public string Video1Path { get => _video1Path; set { this.RaiseAndSetIfChanged(ref _video1Path, value); this.RaisePropertyChanged(nameof(CanCompare)); } }

        private string _video2Path = "";
        public string Video2Path { get => _video2Path; set { this.RaiseAndSetIfChanged(ref _video2Path, value); this.RaisePropertyChanged(nameof(CanCompare)); } }

        private AvaloniaBitmap? _preview1;
        public AvaloniaBitmap? Preview1 { get => _preview1; set => this.RaiseAndSetIfChanged(ref _preview1, value); }

        private AvaloniaBitmap? _preview2;
        public AvaloniaBitmap? Preview2 { get => _preview2; set => this.RaiseAndSetIfChanged(ref _preview2, value); }

        private AvaloniaBitmap? _diffPreview;
        public AvaloniaBitmap? DiffPreview { get => _diffPreview; set => this.RaiseAndSetIfChanged(ref _diffPreview, value); }

        private string _resultText = "No comparison performed yet.";
        public string ResultText { get => _resultText; set => this.RaiseAndSetIfChanged(ref _resultText, value); }

        // ---------- Common ----------
        private string _statusMessage = "Ready";
        public string StatusMessage { get => _statusMessage; set => this.RaiseAndSetIfChanged(ref _statusMessage, value); }

        private double _progressValue = 0;
        public double ProgressValue { get => _progressValue; set => this.RaiseAndSetIfChanged(ref _progressValue, value); }

        private bool _isProcessing = false;
        public bool IsProcessing { get => _isProcessing; set => this.RaiseAndSetIfChanged(ref _isProcessing, value); }

        private AvaloniaBitmap? _videoPreview;
        public AvaloniaBitmap? VideoPreview
        {
            get => _videoPreview;
            set
            {
                if (_videoPreview != value)
                {
                    _videoPreview?.Dispose();
                    this.RaiseAndSetIfChanged(ref _videoPreview, value);
                }
            }
        }

        // ---------- playback state ----------
        private readonly object _previewLock = new();
        private List<GdiBitmap>? _previewFrames;
        private int _previewIndex;
        private bool _isPreviewPlaying;
        private readonly int _previewFps = 25;

        // ---------- Charts ----------
        public ISeries[] EmbeddingProgressSeries { get; }
        public ISeries[] ExtractionProgressSeries { get; }
        public ISeries[] PsnrSeries { get; }
        public ISeries[] PerformanceSeries { get; }
        public ISeries[] CapacitySeries { get; }
        public ISeries[] AccuracySeries { get; }

        public ICartesianAxis[] ProgressXAxis { get; }
        public ICartesianAxis[] MetricsXAxis { get; }
        public ICartesianAxis[] PsnrXAxis { get; }

        private static readonly SKColor Navy = new(0, 22, 58);
        private static readonly SKColor Lilac = new(189, 140, 255);

        private static SolidColorPaint NavyStroke(float thickness = 3) =>
            new(Navy) { StrokeThickness = thickness };

        private static SolidColorPaint LilacStroke(float thickness = 3) =>
            new(Lilac) { StrokeThickness = thickness };

        private static SolidColorPaint LilacFill(byte alpha = 60) =>
            new(new SKColor(Lilac.Red, Lilac.Green, Lilac.Blue, alpha));

        private static SolidColorPaint NavyFill(byte alpha = 60) =>
            new(new SKColor(Navy.Red, Navy.Green, Navy.Blue, alpha));

        // ---------- Can* ----------
        public bool CanEmbed =>
            !string.IsNullOrWhiteSpace(HiddenMessage) &&
            !string.IsNullOrWhiteSpace(EncryptionKey) &&
            EncryptionKey.Length >= MinKeyLength &&
            EncryptionKey.Length <= MaxKeyLength &&
            !string.IsNullOrWhiteSpace(CoverVideoPath);

        public bool CanExtract =>
            !string.IsNullOrWhiteSpace(SecretKey) &&
            SecretKey.Length >= MinKeyLength &&
            SecretKey.Length <= MaxKeyLength &&
            !string.IsNullOrWhiteSpace(VideoPath);

        public bool CanCompare =>
            !string.IsNullOrWhiteSpace(Video1Path) &&
            !string.IsNullOrWhiteSpace(Video2Path);

        // ---------- Commands ----------
        public ReactiveCommand<Unit, Unit> SelectCoverCommand { get; }
        public ReactiveCommand<Unit, Unit> SelectStegoCommand { get; }
        public ReactiveCommand<Unit, Unit> EmbedCommand { get; }
        public ReactiveCommand<Unit, Unit> ExtractCommand { get; }
        public ReactiveCommand<Unit, Unit> BrowseVideo1Command { get; }
        public ReactiveCommand<Unit, Unit> BrowseVideo2Command { get; }
        public ReactiveCommand<Unit, Unit> CompareVideosCommand { get; }
        public ReactiveCommand<Unit, Unit> ClearCommand { get; }
        public ReactiveCommand<Unit, Unit> ShowMenuCommand { get; }
        public ReactiveCommand<Unit, Unit> ShowEmbedCommand { get; }
        public ReactiveCommand<Unit, Unit> ShowExtractCommand { get; }
        public ReactiveCommand<Unit, Unit> ShowCompareCommand { get; }

        public MainWindowViewModel()
        {
            var uiScheduler = AvaloniaScheduler.Instance;

            SelectCoverCommand = ReactiveCommand.CreateFromTask(SelectCoverVideoAsync, outputScheduler: uiScheduler);
            SelectStegoCommand = ReactiveCommand.CreateFromTask(SelectStegoVideoAsync, outputScheduler: uiScheduler);
            EmbedCommand = ReactiveCommand.CreateFromTask(EmbedAsync, outputScheduler: uiScheduler);
            ExtractCommand = ReactiveCommand.CreateFromTask(ExtractAsync, outputScheduler: uiScheduler);
            BrowseVideo1Command = ReactiveCommand.CreateFromTask(BrowseVideo1Async, outputScheduler: uiScheduler);
            BrowseVideo2Command = ReactiveCommand.CreateFromTask(BrowseVideo2Async, outputScheduler: uiScheduler);
            CompareVideosCommand = ReactiveCommand.CreateFromTask(CompareVideosAsync, outputScheduler: uiScheduler);

            ClearCommand = ReactiveCommand.Create(ClearCompare, outputScheduler: uiScheduler);
            ShowMenuCommand = ReactiveCommand.Create(ShowMenu, outputScheduler: uiScheduler);
            ShowEmbedCommand = ReactiveCommand.Create(ShowEmbed, outputScheduler: uiScheduler);
            ShowExtractCommand = ReactiveCommand.Create(ShowExtract, outputScheduler: uiScheduler);
            ShowCompareCommand = ReactiveCommand.Create(ShowCompare, outputScheduler: uiScheduler);

            // --- series, axes init ---
            EmbeddingProgressSeries = new ISeries[]
            {
                new LineSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Stroke = NavyStroke(3),
                    Fill   = LilacFill(35),
                    GeometrySize = 6,
                    GeometryFill = NavyFill(220),
                    GeometryStroke = LilacStroke(2),
                    Name = "Embedding %"
                }
            };

            ExtractionProgressSeries = new ISeries[]
            {
                new LineSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Stroke = LilacStroke(3),
                    Fill   = NavyFill(35),
                    GeometrySize = 6,
                    GeometryFill = LilacFill(220),
                    GeometryStroke = NavyStroke(2),
                    Name = "Extraction %"
                }
            };

            PsnrSeries = new ISeries[]
            {
                new LineSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Stroke = NavyStroke(3),
                    Fill   = LilacFill(30),
                    GeometrySize = 5,
                    GeometryFill = LilacFill(220),
                    GeometryStroke = NavyStroke(2),
                    Name = "PSNR (dB)"
                }
            };

            PerformanceSeries = new ISeries[]
            {
                new ColumnSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Name = "Time (s)",
                    Fill = LilacFill(180),
                    Stroke = NavyStroke(2)
                }
            };

            CapacitySeries = new ISeries[]
            {
                new ColumnSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Name = "Bits/frame",
                    Fill = NavyFill(180),
                    Stroke = LilacStroke(2)
                }
            };

            AccuracySeries = new ISeries[]
            {
                new ColumnSeries<double>
                {
                    Values = new ObservableCollection<double>(),
                    Name = "Accuracy %",
                    Fill = new SolidColorPaint(new SKColor(27, 159, 255, 180)),
                    Stroke = LilacStroke(2)
                }
            };

            ProgressXAxis = new ICartesianAxis[]
            {
                new Axis
                {
                    Name = "Step",
                    Labels = Array.Empty<string>(),
                    LabelsPaint = new SolidColorPaint(new SKColor(180, 190, 210)),
                    SeparatorsPaint = new SolidColorPaint(new SKColor(40, 60, 90))
                    {
                        StrokeThickness = 1,
                        PathEffect = new DashEffect(new float[] { 3, 3 })
                    },
                    TicksPaint = new SolidColorPaint(new SKColor(80, 100, 130))
                    {
                        StrokeThickness = 1
                    }
                }
            };

            MetricsXAxis = new ICartesianAxis[]
            {
                new Axis
                {
                    Labels = new[] { "1", "2", "3" },
                    LabelsPaint = new SolidColorPaint(new SKColor(180, 190, 210)),
                    SeparatorsPaint = new SolidColorPaint(new SKColor(40, 60, 90))
                    {
                        StrokeThickness = 1
                    },
                    TicksPaint = new SolidColorPaint(new SKColor(80, 100, 130))
                    {
                        StrokeThickness = 1
                    }
                }
            };

            PsnrXAxis = new ICartesianAxis[]
            {
                new Axis
                {
                    Name = "Frame",
                    Labels = Array.Empty<string>(),
                    LabelsPaint = new SolidColorPaint(new SKColor(180, 190, 210)),
                    SeparatorsPaint = new SolidColorPaint(new SKColor(40, 60, 90))
                    {
                        StrokeThickness = 1,
                        PathEffect = new DashEffect(new float[] { 3, 3 })
                    },
                    TicksPaint = new SolidColorPaint(new SKColor(80, 100, 130))
                    {
                        StrokeThickness = 1
                    }
                }
            };

            // --- playback timer ---
            var interval = TimeSpan.FromMilliseconds(1000.0 / _previewFps);
            DispatcherTimer.Run(() =>
            {
                if (!_isPreviewPlaying || _previewFrames == null || _previewFrames.Count == 0)
                    return true;

                lock (_previewLock)
                {
                    if (_previewFrames == null || _previewFrames.Count == 0) return true;

                    _previewIndex++;
                    if (_previewIndex >= _previewFrames.Count)
                        _previewIndex = 0;

                    var frame = _previewFrames[_previewIndex];
                    var bmp = ConvertToAvaloniaBitmap(frame);
                    if (bmp != null)
                        VideoPreview = bmp;
                }
                return true;
            }, interval);
        }

        // ---------- View switching ----------
        private void ResetCommon()
        {
            VideoPreview = null;
            ProgressValue = 0;
            StatusMessage = "Ready";
            ClearChartData();

            lock (_previewLock)
            {
                _isPreviewPlaying = false;
                _previewFrames?.Clear();
                _previewFrames = null;
                _previewIndex = 0;
            }
        }

        private void ShowMenu()
        {
            IsMenuVisible = true;
            IsEmbedVisible = false;
            IsExtractVisible = false;
            IsCompareVisible = false;
            HiddenMessage = "";
            EncryptionKey = "";
            SecretKey = "";
            CoverVideoPath = "";
            VideoPath = "";
            ExtractedMessage = "";
            ResetCommon();
        }

        private void ShowEmbed()
        {
            IsMenuVisible = false;
            IsEmbedVisible = true;
            IsExtractVisible = false;
            IsCompareVisible = false;
            SecretKey = "";
            VideoPath = "";
            ExtractedMessage = "";
            ResetCommon();
        }

        private void ShowExtract()
        {
            IsMenuVisible = false;
            IsEmbedVisible = false;
            IsExtractVisible = true;
            IsCompareVisible = false;
            HiddenMessage = "";
            EncryptionKey = "";
            CoverVideoPath = "";
            ResetCommon();
        }

        private void ShowCompare()
        {
            IsMenuVisible = false;
            IsEmbedVisible = false;
            IsExtractVisible = false;
            IsCompareVisible = true;
            ResetCommon();
        }

        private void ClearChartData()
        {
            ((ObservableCollection<double>)((LineSeries<double>)EmbeddingProgressSeries[0]).Values).Clear();
            ((ObservableCollection<double>)((LineSeries<double>)ExtractionProgressSeries[0]).Values).Clear();
            ((ObservableCollection<double>)((LineSeries<double>)PsnrSeries[0]).Values).Clear();
            ((ObservableCollection<double>)((ColumnSeries<double>)PerformanceSeries[0]).Values).Clear();
            ((ObservableCollection<double>)((ColumnSeries<double>)CapacitySeries[0]).Values).Clear();
            ((ObservableCollection<double>)((ColumnSeries<double>)AccuracySeries[0]).Values).Clear();

            if (ProgressXAxis[0] is Axis ax1) ax1.Labels = Array.Empty<string>();
            if (PsnrXAxis[0] is Axis ax2) ax2.Labels = Array.Empty<string>();
        }

        // ---------- File picker ----------
        private async Task<IReadOnlyList<IStorageFile>?> PickVideoFile(string title)
        {
            var topLevel = TopLevel.GetTopLevel(GetMainWindow());
            if (topLevel?.StorageProvider == null) return null;

            return await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Video Files")
                    {
                        Patterns = new[] { "*.avi", "*.mp4", "*.mkv", "*.mov" }
                    }
                }
            });
        }

        private static TopLevel? GetMainWindow() =>
            Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
                ? TopLevel.GetTopLevel(desktop.MainWindow) : null;

        private async Task SelectCoverVideoAsync()
        {
            var files = await PickVideoFile("Select Cover Video");
            if (files?.Count > 0) CoverVideoPath = files[0].Path.LocalPath;
        }

        private async Task SelectStegoVideoAsync()
        {
            var files = await PickVideoFile("Select Stego Video");
            if (files?.Count > 0) VideoPath = files[0].Path.LocalPath;
        }

        private async Task BrowseVideo1Async()
        {
            var files = await PickVideoFile("Select Original Video");
            if (files?.Count > 0)
            {
                Video1Path = files[0].Path.LocalPath;
                await LoadThumbnailAsync(Video1Path, bmp => Preview1 = bmp);
            }
        }

        private async Task BrowseVideo2Async()
        {
            var files = await PickVideoFile("Select Stego/Restored Video");
            if (files?.Count > 0)
            {
                Video2Path = files[0].Path.LocalPath;
                await LoadThumbnailAsync(Video2Path, bmp => Preview2 = bmp);
            }
        }

        private async Task LoadThumbnailAsync(string path, Action<AvaloniaBitmap?> setPreview)
        {
            await Task.Run(() =>
            {
                try
                {
                    var frames = VideoHelperFFmpeg.LoadFrames(path, maxWidth: 300);
                    if (frames.Count > 0)
                    {
                        var frame = frames[0];
                        var bmp = ConvertToAvaloniaBitmap(frame);
                        Dispatcher.UIThread.Post(() => setPreview(bmp));
                    }
                    foreach (var f in frames) f.Dispose();
                }
                catch (Exception ex)
                {
                    Dispatcher.UIThread.Post(() => StatusMessage = $"Thumbnail error: {ex.Message}");
                }
            });
        }

        // ---------- Safe Bitmap Conversion ----------
        private AvaloniaBitmap? ConvertToAvaloniaBitmap(GdiBitmap? bitmap)
        {
            if (bitmap == null) return null;

            try
            {
                if (bitmap.Width <= 0 || bitmap.Height <= 0)
                {
                    return null;
                }

                using var ms = new MemoryStream();
                bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                ms.Position = 0;

                var avaloniaBmp = new AvaloniaBitmap(ms);
                return avaloniaBmp;
            }
            catch
            {
                return null;
            }
        }

        // ---------- Safe Diff Preview ----------
        private GdiBitmap CreateDiffPreview(GdiBitmap? img1, GdiBitmap? img2)
        {
            if (img1 == null || img2 == null || img1.Width != img2.Width || img1.Height != img2.Height)
                return new GdiBitmap(1, 1);

            var diff = new GdiBitmap(img1.Width, img1.Height);
            using var acc1 = new FastBitmapAccessor(img1);
            using var acc2 = new FastBitmapAccessor(img2);
            using var accD = new FastBitmapAccessor(diff);
            acc1.Lock(); acc2.Lock(); accD.Lock();

            for (int y = 0; y < img1.Height; y++)
            {
                for (int x = 0; x < img1.Width; x++)
                {
                    byte rDiff = (byte)Math.Abs(acc1.GetRed(x, y) - acc2.GetRed(x, y));
                    byte gDiff = (byte)Math.Abs(acc1.GetGreen(x, y) - acc2.GetGreen(x, y));
                    byte bDiff = (byte)Math.Abs(acc1.GetBlue(x, y) - acc2.GetBlue(x, y));
                    byte gray = (byte)((rDiff + gDiff + bDiff) / 3);

                    accD.SetRed(x, y, gray);
                    accD.SetGreen(x, y, gray);
                    accD.SetBlue(x, y, gray);
                }
            }

            acc1.Unlock(); acc2.Unlock(); accD.Unlock();
            return diff;
        }

        // ---------- Embed ----------
        private async Task EmbedAsync()
        {
            if (!CanEmbed) return;

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                IsProcessing = true;
                StatusMessage = "Embedding...";
                ProgressValue = 0;
                ClearChartData();
            });

            var sw = System.Diagnostics.Stopwatch.StartNew();

            await Task.Run(() =>
            {
                try
                {
                    var info = VideoHelperFFmpeg.GetVideoInfo(CoverVideoPath);
                    var frames = VideoHelperFFmpeg.LoadFrames(CoverVideoPath);

                    lock (_previewLock)
                    {
                        _previewFrames = frames;
                        _previewIndex = 0;
                        _isPreviewPlaying = true;
                    }

                    long totalPixels = (long)frames.Count * frames[0].Width * frames[0].Height;

                    var embedVals = (ObservableCollection<double>)((LineSeries<double>)EmbeddingProgressSeries[0]).Values;
                    var psnrVals = (ObservableCollection<double>)((LineSeries<double>)PsnrSeries[0]).Values;
                    var progressAxis = (Axis)ProgressXAxis[0];
                    var progressLabels = new List<string>();

                    Action<int, GdiBitmap?> progress = (p, frm) =>
                    {
                        Dispatcher.UIThread.Post(() =>
                        {
                            ProgressValue = p;
                            embedVals.Add(p);
                            progressLabels.Add((progressLabels.Count + 1).ToString());
                            progressAxis.Labels = progressLabels.ToArray();
                            if (frm != null)
                            {
                                using var clone = (GdiBitmap)frm.Clone();
                                VideoPreview = ConvertToAvaloniaBitmap(clone);
                            }
                        });
                    };

                    var stegoFrames = StegoCore.EmbedVideo(frames, HiddenMessage, EncryptionKey, progress);

                    int step = Math.Max(1, stegoFrames.Count / 50);
                    var psnrAxis = (Axis)PsnrXAxis[0];
                    var psnrLabels = new List<string>();

                    for (int i = 0; i < frames.Count && i < stegoFrames.Count; i += step)
                    {
                        double psnr = StegoCore.ComputeFramePSNR(frames[i], stegoFrames[i]);
                        int frameIndex = i + 1;
                        double localPsnr = psnr;

                        Dispatcher.UIThread.Post(() =>
                        {
                            psnrVals.Add(localPsnr);
                            psnrLabels.Add(frameIndex.ToString());
                            psnrAxis.Labels = psnrLabels.ToArray();
                        });
                    }

                    string directory = Path.GetDirectoryName(CoverVideoPath) ?? ".";
                    string outPath = Path.Combine(directory, "stego_" + Path.GetFileName(CoverVideoPath));

                    VideoHelperFFmpeg.SaveLosslessAVI(outPath, stegoFrames, info.FrameRate, CoverVideoPath);

                    lock (_previewLock)
                    {
                        _previewFrames = stegoFrames;
                        _previewIndex = 0;
                        _isPreviewPlaying = true;
                    }

                    sw.Stop();
                    double seconds = sw.Elapsed.TotalSeconds;

                    Dispatcher.UIThread.Post(() =>
                    {
                        ProgressValue = 100;
                        StatusMessage = $"Done! Saved: {outPath}";
                        UpdateExperimentCharts(seconds, totalPixels, HiddenMessage.Length, true);
                    });

                    foreach (var f in frames) f.Dispose();
                }
                catch (Exception ex)
                {
                    Dispatcher.UIThread.Post(() => StatusMessage = $"Error: {ex.Message}");
                }
                finally
                {
                    Dispatcher.UIThread.Post(() => IsProcessing = false);
                }
            });
        }

        // ---------- Extract ----------
        private async Task ExtractAsync()
        {
            if (!CanExtract) return;

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                IsProcessing = true;
                StatusMessage = "Extracting...";
                ProgressValue = 0;
                ClearChartData();
            });

            var sw = System.Diagnostics.Stopwatch.StartNew();

            await Task.Run(() =>
            {
                try
                {
                    var frames = VideoHelperFFmpeg.LoadFrames(VideoPath);

                    lock (_previewLock)
                    {
                        _previewFrames = frames;
                        _previewIndex = 0;
                        _isPreviewPlaying = true;
                    }

                    long totalPixels = (long)frames.Count * frames[0].Width * frames[0].Height;

                    var extractVals = (ObservableCollection<double>)((LineSeries<double>)ExtractionProgressSeries[0]).Values;
                    var progressAxis = (Axis)ProgressXAxis[0];
                    var progressLabels = new List<string>();

                    Action<int, GdiBitmap?> progress = (p, frm) =>
                    {
                        Dispatcher.UIThread.Post(() =>
                        {
                            ProgressValue = p;
                            extractVals.Add(p);
                            progressLabels.Add((progressLabels.Count + 1).ToString());
                            progressAxis.Labels = progressLabels.ToArray();

                            if (frm != null)
                            {
                                try
                                {
                                    using var clone = (GdiBitmap)frm.Clone();
                                    VideoPreview = ConvertToAvaloniaBitmap(clone);
                                }
                                finally
                                {
                                    // consumer must release the producer's clone
                                    frm.Dispose();
                                }
                            }
                        });
                    };

                    var result = StegoCore.ExtractVideo(
                        frames,
                        SecretKey,
                        m => Dispatcher.UIThread.Post(() => ExtractedMessage = m ?? string.Empty),
                        progress);

                    var restored = frames;
                    string msg = result.Message;

                    string directory = Path.GetDirectoryName(VideoPath) ?? ".";
                    string outPath = Path.Combine(directory, "recovered_" + Path.GetFileName(VideoPath));

                    var info = VideoHelperFFmpeg.GetVideoInfo(VideoPath);
                    VideoHelperFFmpeg.SaveLosslessAVI(outPath, restored, info.FrameRate, VideoPath);

                    lock (_previewLock)
                    {
                        _previewFrames = restored;
                        _previewIndex = 0;
                        _isPreviewPlaying = true;
                    }

                    sw.Stop();
                    double seconds = sw.Elapsed.TotalSeconds;

                    Dispatcher.UIThread.Post(() =>
                    {
                        ProgressValue = 100;
                        StatusMessage = result.HasError
                            ? result.Error
                            : $"Done! Message extracted. Saved: {outPath}";

                        bool ok = !result.HasError && result.HashValid && !string.IsNullOrEmpty(result.Message);
                        UpdateExperimentCharts(seconds, totalPixels, msg?.Length ?? 0, ok);
                    });
                }
                catch (Exception ex)
                {
                    Dispatcher.UIThread.Post(() => StatusMessage = $"Error: {ex.Message}");
                }
                finally
                {
                    Dispatcher.UIThread.Post(() => IsProcessing = false);
                }
            });
        }

        // ---------- Compare ----------
        private async Task CompareVideosAsync()
        {
            if (!CanCompare) return;

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                IsProcessing = true;
                StatusMessage = "Comparing...";
                ProgressValue = 0;
                ClearChartData();
            });

            await Task.Run(() =>
            {
                try
                {
                    var f1 = VideoHelperFFmpeg.LoadFrames(Video1Path);
                    var f2 = VideoHelperFFmpeg.LoadFrames(Video2Path);

                    if (f1.Count == 0 || f2.Count == 0)
                    {
                        Dispatcher.UIThread.Post(() => ResultText = "One or both videos are empty.");
                        return;
                    }

                    int minCount = Math.Min(f1.Count, f2.Count);

                    var info1 = VideoHelperFFmpeg.GetVideoInfo(Video1Path);
                    var info2 = VideoHelperFFmpeg.GetVideoInfo(Video2Path);

                    lock (_previewLock)
                    {
                        _previewFrames = f2;
                        _previewIndex = 0;
                        _isPreviewPlaying = true;
                    }

                    var psnrVals = (ObservableCollection<double>)((LineSeries<double>)PsnrSeries[0]).Values;
                    var psnrAxis = (Axis)PsnrXAxis[0];
                    var psnrLabels = new List<string>();

                    double sum = 0;
                    int sampledCount = 0;
                    int step = Math.Max(1, minCount / 100);

                    for (int i = 0; i < minCount; i += step)
                    {
                        double psnr = StegoCore.ComputeFramePSNR(f1[i], f2[i]);
                        sum += psnr;
                        sampledCount++;

                        int idx = i;
                        int frameIndex = i + 1;
                        double localPsnr = psnr;
                        Dispatcher.UIThread.Post(() =>
                        {
                            ProgressValue = (idx + 1) * 100.0 / minCount;
                            psnrVals.Add(localPsnr);
                            psnrLabels.Add(frameIndex.ToString());
                            psnrAxis.Labels = psnrLabels.ToArray();

                            using var c1 = (GdiBitmap)f1[idx].Clone();
                            using var c2 = (GdiBitmap)f2[idx].Clone();
                            Preview1 = ConvertToAvaloniaBitmap(c1);
                            Preview2 = ConvertToAvaloniaBitmap(c2);
                        });
                    }

                    double avg = sampledCount > 0 ? sum / sampledCount : 0;

                    GdiBitmap? base1 = null;
                    GdiBitmap? base2 = null;
                    GdiBitmap? diff = null;
                    try
                    {
                        base1 = (GdiBitmap)f1[0].Clone();
                        base2 = (GdiBitmap)f2[0].Clone();
                        diff = CreateDiffPreview(base1, base2);
                        var diffBmp = ConvertToAvaloniaBitmap(diff);

                        string meta =
                            $"Video 1: {info1.Width}x{info1.Height}, {info1.FrameRate} fps, {info1.Duration}\n" +
                            $"Video 2: {info2.Width}x{info2.Height}, {info2.FrameRate} fps, {info2.Duration}";

                        Dispatcher.UIThread.Post(() =>
                        {
                            DiffPreview = diffBmp;
                            ResultText =
                                $"{meta}\nAverage PSNR: {avg:F2} dB (sampled {sampledCount} frames)";
                        });
                    }
                    finally
                    {
                        base1?.Dispose();
                        base2?.Dispose();
                        diff?.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.UIThread.Post(() => ResultText = $"Error: {ex.Message}");
                }
                finally
                {
                    Dispatcher.UIThread.Post(() => IsProcessing = false);
                }
            });
        }

        // ---------- Clear compare + experiments ----------
        private void ClearCompare()
        {
            Video1Path = Video2Path = "";
            Preview1 = null;
            Preview2 = null;
            DiffPreview = null;
            ResultText = "No comparison performed yet.";
            ResetCommon();
        }

        // NOTE: naya parameter added: bool success
        private void UpdateExperimentCharts(double seconds, long totalPixels, int messageChars, bool success)
        {
            double payloadBits = (messageChars * 8.0) + 32 * 8 + 32;
            double bitsPerPixel = totalPixels > 0 ? (payloadBits * 2) / totalPixels : 0;

            var perfVals = (ObservableCollection<double>)((ColumnSeries<double>)PerformanceSeries[0]).Values;
            var capVals = (ObservableCollection<double>)((ColumnSeries<double>)CapacitySeries[0]).Values;
            var accVals = (ObservableCollection<double>)((ColumnSeries<double>)AccuracySeries[0]).Values;

            perfVals.Clear();
            capVals.Clear();
            accVals.Clear();

            perfVals.Add(seconds);
            capVals.Add(bitsPerPixel);
            accVals.Add(success ? 100.0 : 0.0);
        }
    }
}
