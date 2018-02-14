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
            //OldBootstrapperCode(f);
            UsingExtracedCecil(f);
            
            Console.ReadLine();
        }

        private static void OldBootstrapperCode(string f)
        {
            string v = null;
            var watch = Stopwatch.StartNew();
            for (int i = 0; i < 1000; i++)
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
            Version v = null;
            var watch = Stopwatch.StartNew();
            for (int i = 0; i < 1; i++)
            {
                using (var s = File.OpenRead(f))
                {
                    v = AssemblyVersionReader.TryRead(s);
                }
            }
            watch.Stop();
            Console.WriteLine("Version = {0}", v);
            Console.WriteLine("Time CECIL = {0}ms", watch.ElapsedMilliseconds);
        }
    }
}

