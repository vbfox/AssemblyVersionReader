using PEFile;
using System;
using System.IO;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            var f = @"G:\Code\vbfox-blog\paket.exe";
            using (var s = File.OpenRead(f))
            {
                var v = ImageReader.ReadAssemblyVersion(s);
                Console.WriteLine("Version = {0}", v);
            }
            Console.ReadLine();
        }
    }
}

