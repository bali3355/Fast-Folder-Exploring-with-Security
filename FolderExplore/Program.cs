﻿using System.Diagnostics;

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
            TestEnumeratingFiles(FolderExplore.Explore(SearchPath, true, true), "Folder.EnumerateFiles");
            stopwatch.Start();
            TestEnumeratingFiles(FolderExplore2.Start(SearchPath, false, true, true), "Folder.EnumerateFiles");
            Console.WriteLine(new string('-', header.Length));
            //var missing = results.Select(x => x.FullName).Except(resultsDefault.Select(x => x.FullName)).ToList();
            //var duplicates = results.Select(x => x.FullName).GroupBy(x => x).Where(x => x.Count() > 1).Select(x => x.Key);
            //Parallel.ForEach(missing, result =>
            //{
            //    Console.WriteLine(result);
            //});
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
