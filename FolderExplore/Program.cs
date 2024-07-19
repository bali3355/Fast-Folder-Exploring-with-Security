using FolderExploring;
using System.Diagnostics;

namespace FastDirTest
{
    public static class StopwatchExtensions
    {
        public static TimeSpan End(this Stopwatch stopwatch)
        {
            if (!stopwatch.IsRunning) return TimeSpan.Zero;
            TimeSpan time = stopwatch.Elapsed;
            stopwatch.Reset();
            return time;

        }
    }
    internal class Program
    {
        internal const int nameWidth = 30, timeWidth = 30, countWidth = 30;
        internal static Stopwatch stopwatch = new();
        internal static int Count { get; set; }
        internal static string SearchPath { get; } = @"C:\";
        internal static TimeSpan Time { get; set; }

        private static void Main(string[] args)
        {


            Console.WriteLine($"Hello, World! {SearchPath}\n");
            string header = $"| {"Enumerator name",-nameWidth} | {"Enumerating Time",-timeWidth} | {"Enumerated Count",-countWidth} |";
            Console.WriteLine(header);
            Console.WriteLine(new string('-', header.Length));

            stopwatch.Start();
            var results = TestEnumeratingFiles(FolderExplore.EnumerateFileSystem(SearchPath, "*", SearchOption.AllDirectories, SearchFor.Files), "Search").ToList();
            Console.WriteLine(new string('-', header.Length));
            Console.WriteLine("\n\nPress any key to exit...");
            Console.ReadKey();
            Parallel.ForEach(results, result =>
            {
                Console.WriteLine(result.FullName);
            });
            Console.ReadKey();

        }

        private static IEnumerable<T> TestEnumeratingFiles<T>(IEnumerable<T> listOfFiles, string name)
        {
            Count = listOfFiles.Count();
            Time = stopwatch.End();
            Console.WriteLine($"| {name,-nameWidth} | {Time,-timeWidth} | {Count,-countWidth} |");
            return listOfFiles;
        }
    }
}
