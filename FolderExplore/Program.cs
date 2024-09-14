using System.Diagnostics;

namespace FolderExplore
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
        internal const int nameWidth = 50, timeWidth = 30, countWidth = 30;
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
            TestEnumeratingFiles(FolderTraversalCore.GetFiles(SearchPath), "GetFiles - Normal without anything");

            stopwatch.Start();
            var fCore2 = FolderTraversalCore2.EnumerateFileSystem(SearchPath, "*", SearchFor.Files, -1, true, true);
            TestEnumeratingFiles(fCore2, "FolderTraversalCore2.EnumerateFileSystem");

            stopwatch.Start();
            var fCore1 = FolderTraversalCore.Start(SearchPath, SearchFor.Files, true, true);
            TestEnumeratingFiles(fCore1, "FolderTraversalCore.Start");

            Console.WriteLine(new string('-', header.Length));
            Console.WriteLine("\n\nPress any key to exit...");
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
