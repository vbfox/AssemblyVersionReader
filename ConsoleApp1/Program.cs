using PEFile;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            var f = @"G:\Code\vbfox-blog\paket.exe";
            UsingExtracedCecil(f);
            //OldBootstrapperCode(f);
            //UsingExtracedCecil(f);
            //OldBootstrapperCode(f);

            Console.ReadLine();
        }

        private static void OldBootstrapperCode(string f)
        {
            string v = null;
            var watch = Stopwatch.StartNew();
            for (int i = 0; i < 1; i++)
            {
                using (var s = File.OpenRead(f))
                {
                    var bytes = new MemoryStream();
                    s.CopyTo(bytes);
                    var attr = Assembly.Load(bytes.ToArray()).GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false).Cast<AssemblyInformationalVersionAttribute>().FirstOrDefault();
                    v = attr.InformationalVersion;
                }
            }
            watch.Stop();
            Console.WriteLine("Version = {0}", v);
            Console.WriteLine("Time LOAD = {0}ms", watch.ElapsedMilliseconds);
        }

        private static void UsingExtracedCecil(string f)
        {
            string v = null;
            var watch = Stopwatch.StartNew();
            for (int i = 0; i < 1; i++)
            {
                using (var s = File.OpenRead(f))
                {
                    var bytes = new MemoryStream();
                    s.CopyTo(bytes);
                    bytes.Position = 0;
                    v = AssemblyVersionReader.TryRead(bytes);
                }
            }
            watch.Stop();
            Console.WriteLine("Version = {0}", v);
            Console.WriteLine("Time CECIL = {0}ms", watch.ElapsedMilliseconds);
        }
    }
}

