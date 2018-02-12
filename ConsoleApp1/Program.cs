using PEFile;
using System;
using System.Diagnostics;
using System.IO;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            var f = @"G:\Code\vbfox-blog\paket.exe";
            Version v = null;
            var watch = Stopwatch.StartNew();
            using (var s = File.OpenRead(f))
            {
                v = AssemblyVersionReader.TryRead(s);
            }
            watch.Stop();
            Console.WriteLine("Version = {0}", v);
            Console.WriteLine("Time = {0}ms", watch.ElapsedMilliseconds);
            Console.ReadLine();
        }
    }
}

