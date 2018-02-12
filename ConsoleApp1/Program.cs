using PEFile;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            var f = @"G:\Code\vbfox-blog\paket.exe";
            var s = File.OpenRead(f);
            var reader = new ImageReader(s, f);
            reader.ReadImage();
            var x = reader.image;

            var hasAssembly = x.TableHeap.HasTable(Table.Assembly);
            var assemblyTable = x.TableHeap[Table.Assembly];

            var headDataReader = new BinaryStreamReader(new MemoryStream(x.TableHeap.data));
            headDataReader.MoveTo(assemblyTable.Offset);
            headDataReader.ReadInt32();
            var aa = headDataReader.ReadInt16();
            var bb = headDataReader.ReadInt16();
            var cc = headDataReader.ReadInt16();
            var dd = headDataReader.ReadInt16();

            Console.WriteLine("{0}.{1}.{2}.{3}", aa, bb, cc, dd);
            Console.ReadLine();
        }
    }
}

