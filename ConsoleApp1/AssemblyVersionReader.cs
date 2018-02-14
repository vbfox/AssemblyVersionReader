//
// Author:
//   Jb Evain (jbevain@gmail.com)
//
// Copyright (c) 2008 - 2015 Jb Evain
// Copyright (c) 2008 - 2011 Novell, Inc.
//
// Licensed under the MIT/X11 license.
//

using System;
using System.IO;
using System.Linq;
using System.Text;
using RVA = System.UInt32;

namespace PEFile
{
    sealed class AssemblyVersionReader : BinaryReader
    {
        readonly Image image;

        DataDirectory cli;
        DataDirectory metadata;

        uint table_heap_offset;
        byte heapSizes;

        AssemblyVersionReader(Stream stream)
            : base(stream)
        {
            image = new Image();
        }

        void MoveTo(DataDirectory directory)
        {
            BaseStream.Position = image.ResolveVirtualAddress(directory.VirtualAddress);
        }

        void ReadImage()
        {
            if (BaseStream.Length < 128)
                throw new BadImageFormatException();

            // - DOSHeader

            // PE					2
            // Start				58
            // Lfanew				4
            // End					64

            if (ReadUInt16() != 0x5a4d)
                throw new BadImageFormatException();

            Advance(58);

            MoveTo(ReadUInt32());

            if (ReadUInt32() != 0x00004550)
                throw new BadImageFormatException();

            // - PEFileHeader

            // Machine				2
            Advance(2);

            // NumberOfSections		2
            ushort sections = ReadUInt16();

            // TimeDateStamp		4
            // PointerToSymbolTable	4
            // NumberOfSymbols		4
            // OptionalHeaderSize	2
            Advance(14);

            // Characteristics		2
            ushort characteristics = ReadUInt16();

            ReadOptionalHeaders();
            ReadSections(sections);
            ReadCLIHeader();
            ReadMetadata();
        }

        void ReadOptionalHeaders()
        {
            // - PEOptionalHeader
            //   - StandardFieldsHeader

            // Magic				2
            bool pe64 = ReadUInt16() == 0x20b;

            //						pe32 || pe64

            // CodeSize				4
            // InitializedDataSize	4
            // UninitializedDataSize4
            // EntryPointRVA		4
            // BaseOfCode			4
            // BaseOfData			4 || 0

            //   - NTSpecificFieldsHeader

            // ImageBase			4 || 8
            // SectionAlignment		4
            // FileAlignement		4
            // OSMajor				2
            // OSMinor				2
            // UserMajor			2
            // UserMinor			2
            // SubSysMajor			2
            // SubSysMinor			2
            // Reserved				4
            // ImageSize			4
            // HeaderSize			4
            // FileChecksum			4
            // SubSystem			2
            // DLLFlags				2
            Advance(70);

            // StackReserveSize		4 || 8
            // StackCommitSize		4 || 8
            // HeapReserveSize		4 || 8
            // HeapCommitSize		4 || 8
            // LoaderFlags			4
            // NumberOfDataDir		4

            //   - DataDirectoriesHeader

            // ExportTable			8
            // ImportTable			8

            Advance(pe64 ? 56 : 40);

            // ResourceTable		8

            // ExceptionTable		8
            // CertificateTable		8
            // BaseRelocationTable	8
            // Debug				8
            // Copyright			8
            // GlobalPtr			8
            // TLSTable				8
            // LoadConfigTable		8
            // BoundImport			8
            // IAT					8
            // DelayImportDescriptor8
            Advance(96);

            // CLIHeader			8
            cli = ReadDataDirectory();

            if (cli.VirtualAddress == 0 && cli.Size == 0)
                throw new BadImageFormatException();

            // Reserved				8
            Advance(8);
        }

        string ReadAlignedString(int length)
        {
            int read = 0;
            var buffer = new char[length];
            while (read < length)
            {
                var current = ReadByte();
                if (current == 0)
                    break;

                buffer[read++] = (char)current;
            }

            Advance(-1 + ((read + 4) & ~3) - read);

            return new string(buffer, 0, read);
        }

        void ReadSections(ushort count)
        {
            var sections = new Section[count];

            for (int i = 0; i < count; i++)
            {
                // Name
                // VirtualSize		4
                Advance(12);

                // VirtualAddress	4
                var virtualAddress = ReadUInt32();
                // SizeOfRawData	4
                var sizeOfRawData = ReadUInt32();
                // PointerToRawData	4
                var pointerToRawData = ReadUInt32();

                // PointerToRelocations		4
                // PointerToLineNumbers		4
                // NumberOfRelocations		2
                // NumberOfLineNumbers		2
                // Characteristics			4
                Advance(16);

                sections[i] = new Section(virtualAddress, sizeOfRawData, pointerToRawData);
            }

            image.Sections = sections;
        }

        void ReadCLIHeader()
        {
            MoveTo(cli);

            // - CLIHeader

            // Cb						4
            // MajorRuntimeVersion		2
            // MinorRuntimeVersion		2
            Advance(8);

            // Metadata					8
            metadata = ReadDataDirectory();

            // Flags					4
            // EntryPointToken			4
            // Resources				8
            // StrongNameSignature		8
            // CodeManagerTable			8
            // VTableFixups				8
            // ExportAddressTableJumps	8
            // ManagedNativeHeader		8
        }

        void ReadMetadata()
        {
            MoveTo(metadata);

            if (ReadUInt32() != 0x424a5342)
                throw new BadImageFormatException();

            // MajorVersion			2
            // MinorVersion			2
            // Reserved				4
            Advance(8);

            Advance(ReadInt32());

            // Flags		2
            Advance(2);

            var streams = ReadUInt16();

            var section = image.GetSectionAtVirtualAddress(metadata.VirtualAddress);
            if (section == null)
                throw new BadImageFormatException();

            image.MetadataSection = section.Value;

            for (int i = 0; i < streams; i++)
                ReadMetadataStream(section.Value);

            if (table_heap_offset != 0)
                ReadTableHeap();
        }

        void ReadMetadataStream(Section section)
        {
            // Offset		4
            uint offset = metadata.VirtualAddress - section.VirtualAddress + ReadUInt32(); // relative to the section start

            // Size			4
            uint size = ReadUInt32();

            var offsetInFile = offset + image.MetadataSection.PointerToRawData;

            var name = ReadAlignedString(16);
            switch (name)
            {
                case "#~":
                case "#-":
                    image.TableHeap = new TableHeap(offsetInFile, size);
                    table_heap_offset = offset;
                    break;
                case "#Strings":
                    image.StringHeap = new StringHeap(offsetInFile, size);
                    break;
                case "#Blob":
                    image.BlobHeap = new BlobHeap(offsetInFile, size);
                    break;
            }
        }

        void ReadTableHeap()
        {
            MoveTo(table_heap_offset + image.MetadataSection.PointerToRawData);

            // Reserved			4
            // MajorVersion		1
            // MinorVersion		1
            Advance(6);

            // HeapSizes		1
            heapSizes = ReadByte();

            // Reserved2		1
            Advance(1);

            // Valid			8
            image.TableHeap.Valid = ReadInt64();

            // Sorted			8
            Advance(8);

            for (int i = 0; i < Mixin.TableCount; i++)
            {
                if (!image.TableHeap.HasTable((Table)i))
                    continue;

                image.TableHeap.Tables[i].Length = ReadUInt32();
            }

            ComputeTableInformations();
        }

        int StringIndexSize => (heapSizes & 0x1) > 0 ? 4 : 2;
        int BlobIndexSize => (heapSizes & 0x4) > 0 ? 4 : 2;

        void ComputeTableInformations()
        {
            uint offset = (uint)BaseStream.Position - table_heap_offset - image.MetadataSection.PointerToRawData; // header

            int stridx_size = StringIndexSize;
            int guididx_size = (heapSizes & 0x2) > 0 ? 4 : 2;
            int blobidx_size = BlobIndexSize;

            var heap = image.TableHeap;
            var tables = heap.Tables;

            for (int i = 0; i < Mixin.TableCount; i++)
            {
                var table = (Table)i;
                if (!heap.HasTable(table))
                    continue;

                int size;
                switch (table)
                {
                    case Table.Module:
                        size = 2    // Generation
                            + stridx_size   // Name
                            + (guididx_size * 3);   // Mvid, EncId, EncBaseId
                        break;
                    case Table.TypeRef:
                        size = image.GetCodedIndexSize(CodedIndex.ResolutionScope)    // ResolutionScope
                            + (stridx_size * 2);    // Name, Namespace
                        break;
                    case Table.TypeDef:
                        size = 4    // Flags
                            + (stridx_size * 2) // Name, Namespace
                            + image.GetCodedIndexSize(CodedIndex.TypeDefOrRef)    // BaseType
                            + image.GetTableIndexSize(Table.Field)    // FieldList
                            + image.GetTableIndexSize(Table.Method);  // MethodList
                        break;
                    case Table.FieldPtr:
                        size = image.GetTableIndexSize(Table.Field);  // Field
                        break;
                    case Table.Field:
                        size = 2    // Flags
                            + stridx_size   // Name
                            + blobidx_size; // Signature
                        break;
                    case Table.MethodPtr:
                        size = image.GetTableIndexSize(Table.Method); // Method
                        break;
                    case Table.Method:
                        size = 8    // Rva 4, ImplFlags 2, Flags 2
                            + stridx_size   // Name
                            + blobidx_size  // Signature
                            + image.GetTableIndexSize(Table.Param); // ParamList
                        break;
                    case Table.ParamPtr:
                        size = image.GetTableIndexSize(Table.Param); // Param
                        break;
                    case Table.Param:
                        size = 4    // Flags 2, Sequence 2
                            + stridx_size;  // Name
                        break;
                    case Table.InterfaceImpl:
                        size = image.GetTableIndexSize(Table.TypeDef) // Class
                            + image.GetCodedIndexSize(CodedIndex.TypeDefOrRef);   // Interface
                        break;
                    case Table.MemberRef:
                        size = image.GetCodedIndexSize(CodedIndex.MemberRefParent)    // Class
                            + stridx_size   // Name
                            + blobidx_size; // Signature
                        break;
                    case Table.Constant:
                        size = 2    // Type
                            + image.GetCodedIndexSize(CodedIndex.HasConstant) // Parent
                            + blobidx_size; // Value
                        break;
                    case Table.CustomAttribute:
                        size = image.GetCodedIndexSize(CodedIndex.HasCustomAttribute) // Parent
                            + image.GetCodedIndexSize(CodedIndex.CustomAttributeType) // Type
                            + blobidx_size; // Value
                        break;
                    case Table.FieldMarshal:
                        size = image.GetCodedIndexSize(CodedIndex.HasFieldMarshal)    // Parent
                            + blobidx_size; // NativeType
                        break;
                    case Table.DeclSecurity:
                        size = 2    // Action
                            + image.GetCodedIndexSize(CodedIndex.HasDeclSecurity) // Parent
                            + blobidx_size; // PermissionSet
                        break;
                    case Table.ClassLayout:
                        size = 6    // PackingSize 2, ClassSize 4
                            + image.GetTableIndexSize(Table.TypeDef); // Parent
                        break;
                    case Table.FieldLayout:
                        size = 4    // Offset
                            + image.GetTableIndexSize(Table.Field);   // Field
                        break;
                    case Table.StandAloneSig:
                        size = blobidx_size;    // Signature
                        break;
                    case Table.EventMap:
                        size = image.GetTableIndexSize(Table.TypeDef) // Parent
                            + image.GetTableIndexSize(Table.Event);   // EventList
                        break;
                    case Table.EventPtr:
                        size = image.GetTableIndexSize(Table.Event);  // Event
                        break;
                    case Table.Event:
                        size = 2    // Flags
                            + stridx_size // Name
                            + image.GetCodedIndexSize(CodedIndex.TypeDefOrRef);   // EventType
                        break;
                    case Table.PropertyMap:
                        size = image.GetTableIndexSize(Table.TypeDef) // Parent
                            + image.GetTableIndexSize(Table.Property);    // PropertyList
                        break;
                    case Table.PropertyPtr:
                        size = image.GetTableIndexSize(Table.Property);   // Property
                        break;
                    case Table.Property:
                        size = 2    // Flags
                            + stridx_size   // Name
                            + blobidx_size; // Type
                        break;
                    case Table.MethodSemantics:
                        size = 2    // Semantics
                            + image.GetTableIndexSize(Table.Method)   // Method
                            + image.GetCodedIndexSize(CodedIndex.HasSemantics);   // Association
                        break;
                    case Table.MethodImpl:
                        size = image.GetTableIndexSize(Table.TypeDef) // Class
                            + image.GetCodedIndexSize(CodedIndex.MethodDefOrRef)  // MethodBody
                            + image.GetCodedIndexSize(CodedIndex.MethodDefOrRef); // MethodDeclaration
                        break;
                    case Table.ModuleRef:
                        size = stridx_size; // Name
                        break;
                    case Table.TypeSpec:
                        size = blobidx_size;    // Signature
                        break;
                    case Table.ImplMap:
                        size = 2    // MappingFlags
                            + image.GetCodedIndexSize(CodedIndex.MemberForwarded) // MemberForwarded
                            + stridx_size   // ImportName
                            + image.GetTableIndexSize(Table.ModuleRef);   // ImportScope
                        break;
                    case Table.FieldRVA:
                        size = 4    // RVA
                            + image.GetTableIndexSize(Table.Field);   // Field
                        break;
                    case Table.EncLog:
                        size = 8;
                        break;
                    case Table.EncMap:
                        size = 4;
                        break;
                    case Table.Assembly:
                        size = 16 // HashAlgId 4, Version 4 * 2, Flags 4
                            + blobidx_size  // PublicKey
                            + (stridx_size * 2);    // Name, Culture
                        break;
                    default:
                        throw new NotSupportedException();
                }

                tables[i].RowSize = (uint)size;
                tables[i].Offset = offset;

                offset += (uint)size * tables[i].Length;

                if (table == Table.Assembly)
                {
                    // Tables are in order, after Assembly there are others but we don't care
                    return;
                }
            }
        }

        private void Advance(int bytes)
        {
            BaseStream.Seek(bytes, SeekOrigin.Current);
        }

        private void MoveTo(uint position)
        {
            BaseStream.Seek(position, SeekOrigin.Begin);
        }

        private DataDirectory ReadDataDirectory()
        {
            return new DataDirectory(ReadUInt32(), ReadUInt32());
        }

        uint ReadIndex(CodedIndex codedIndex)
        {
            var size = image.GetCodedIndexSize(codedIndex);
            return size == 2 ? ReadUInt16() : ReadUInt32();
        }

        string ReadIndexedString()
        {
            var index = StringIndexSize == 2 ? ReadUInt16() : ReadUInt32();
            var value = image.StringHeap.Read(BaseStream, index);
            return value;
        }

        private Version ReadAssemblyVersion()
        {
            if (!image.TableHeap.HasTable(Table.Assembly))
            {
                return null;
            }

            uint aivaIndex = 0;
            {
                var typeRefTable = image.TableHeap.Tables[(int)Table.TypeRef];
                for (uint i = 1; i <= typeRefTable.Length; i++)
                {
                    var index = (typeRefTable.RowSize * (i-1));
                    MoveTo(image.TableHeap.offsetInFile + typeRefTable.Offset + index);
                    Advance(image.GetCodedIndexSize(CodedIndex.ResolutionScope));
                    var nameIndex = StringIndexSize == 2 ? ReadUInt16() : ReadUInt32();
                    var nsIndex = StringIndexSize == 2 ? ReadUInt16() : ReadUInt32();
                    var name = image.StringHeap.Read(BaseStream, nameIndex);
                    var ns = image.StringHeap.Read(BaseStream, nsIndex);

                    Console.WriteLine($"[{i}] {ns}.{name}");
                    if (name == "AssemblyInformationalVersionAttribute")
                    {
                        aivaIndex = i;
                        
                        //break;
                    }
                }
            }

            uint aivaIndexMemberRefParent = aivaIndex << 3 | 0x01;// TypeRef

            uint aivaCtorIndex = 0;
            {
                var memberRefTable = image.TableHeap.Tables[(int)Table.MemberRef];
                for (uint i = 1; i <= memberRefTable.Length; i++)
                {
                    /*
                        size = image.GetCodedIndexSize(CodedIndex.MemberRefParent)    // Class
                            + stridx_size   // Name
                            + blobidx_size; // Signature
                     */
                    var index = (memberRefTable.RowSize * (i-1));
                    MoveTo(image.TableHeap.offsetInFile + memberRefTable.Offset + index);
                    var classIndex = ReadIndex(CodedIndex.MemberRefParent);
                    var name = ReadIndexedString();

                    Console.WriteLine($"[{i}] Class={classIndex >> 3} (Tag={classIndex & 0x07}) {name}");
                    if (classIndex == aivaIndexMemberRefParent && name == ".ctor")
                    {
                        aivaCtorIndex = i;
                        
                        //break;
                    }
                }
            }

            var aivaCtorIndexCustomAttributeType = aivaCtorIndex << 3 | 0x03; // MemberRef

            var customAttrTable = image.TableHeap.Tables[(int)Table.CustomAttribute];

            uint aivaBlob = 0;

            for (uint i = 1; i <= customAttrTable.Length; i++)
            {
                /*                        size = image.GetCodedIndexSize(CodedIndex.HasCustomAttribute) // Parent
                            + image.GetCodedIndexSize(CodedIndex.CustomAttributeType) // Type
                            + blobidx_size; // Value
                 */
                MoveTo(image.TableHeap.offsetInFile + customAttrTable.Offset + (customAttrTable.RowSize * (i-1)));
                var target = ReadIndex(CodedIndex.HasCustomAttribute);
                var typeIndex = ReadIndex(CodedIndex.CustomAttributeType);
                var blobIndex = BlobIndexSize == 2 ? ReadUInt16() : ReadUInt32();

                if (typeIndex == aivaCtorIndexCustomAttributeType)
                {
                    Console.WriteLine($"[{i}] {target} Type={typeIndex >> 3} (Tag={typeIndex & 0x07}) {blobIndex}");
                    aivaBlob = blobIndex;
                    //break;
                }
            }

            var blob = image.BlobHeap.Read(BaseStream, aivaBlob);
            // Parse with "II.23.3" of https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf
            var s = new string(blob.Select(b => (char)b).ToArray());

            var assemblyTable = image.TableHeap.Tables[(int)Table.Assembly];

            MoveTo(image.TableHeap.offsetInFile + assemblyTable.Offset);
            Advance(4);

            var major = ReadUInt16();
            var minor = ReadUInt16();
            var build = ReadUInt16();
            var revision = ReadUInt16();

            return new Version(major, minor, build, revision);
        }

        public static Version TryRead(Stream stream)
        {
            /*try
            {*/
                var reader = new AssemblyVersionReader(stream);
                reader.ReadImage();
                return reader.ReadAssemblyVersion();
            /*}
            catch (Exception)
            {
                return null;
            }*/
        }

        struct DataDirectory
        {
            public readonly RVA VirtualAddress;
            public readonly uint Size;

            public DataDirectory(RVA rva, uint size)
            {
                this.VirtualAddress = rva;
                this.Size = size;
            }
        }

        struct Section
        {
            public readonly RVA VirtualAddress;
            public readonly uint SizeOfRawData;
            public readonly uint PointerToRawData;

            public Section(uint virtualAddress, uint sizeOfRawData, uint pointerToRawData)
            {
                VirtualAddress = virtualAddress;
                SizeOfRawData = sizeOfRawData;
                PointerToRawData = pointerToRawData;
            }
        }

        enum CodedIndex
        {
            TypeDefOrRef,
            HasConstant,
            HasCustomAttribute,
            HasFieldMarshal,
            HasDeclSecurity,
            MemberRefParent,
            HasSemantics,
            MethodDefOrRef,
            MemberForwarded,
            Implementation,
            CustomAttributeType,
            ResolutionScope,
            TypeOrMethodDef,
            HasCustomDebugInformation,
        }

        enum Table : byte
        {
            Module = 0x00,
            TypeRef = 0x01,
            TypeDef = 0x02,
            FieldPtr = 0x03,
            Field = 0x04,
            MethodPtr = 0x05,
            Method = 0x06,
            ParamPtr = 0x07,
            Param = 0x08,
            InterfaceImpl = 0x09,
            MemberRef = 0x0a,
            Constant = 0x0b,
            CustomAttribute = 0x0c,
            FieldMarshal = 0x0d,
            DeclSecurity = 0x0e,
            ClassLayout = 0x0f,
            FieldLayout = 0x10,
            StandAloneSig = 0x11,
            EventMap = 0x12,
            EventPtr = 0x13,
            Event = 0x14,
            PropertyMap = 0x15,
            PropertyPtr = 0x16,
            Property = 0x17,
            MethodSemantics = 0x18,
            MethodImpl = 0x19,
            ModuleRef = 0x1a,
            TypeSpec = 0x1b,
            ImplMap = 0x1c,
            FieldRVA = 0x1d,
            EncLog = 0x1e,
            EncMap = 0x1f,
            Assembly = 0x20,
            AssemblyProcessor = 0x21,
            AssemblyOS = 0x22,
            AssemblyRef = 0x23,
            AssemblyRefProcessor = 0x24,
            AssemblyRefOS = 0x25,
            File = 0x26,
            ExportedType = 0x27,
            ManifestResource = 0x28,
            NestedClass = 0x29,
            GenericParam = 0x2a,
            MethodSpec = 0x2b,
            GenericParamConstraint = 0x2c,
        }

        static class Mixin
        {
            public const int TableCount = 58;

            public static uint ReadCompressedUInt32(Stream stream)
            {
                uint integer;
                byte firstByte = (byte)stream.ReadByte();
                if ((firstByte & 0x80) == 0)
                {
                    integer = firstByte;
                }
                else if ((firstByte & 0x40) == 0)
                {
                    integer = (uint)(firstByte & ~0x80) << 8;
                    integer |= (byte)stream.ReadByte();
                }
                else
                {
                    integer = (uint)(firstByte & ~0xc0) << 24;
                    integer |= (uint)((byte)stream.ReadByte()) << 16;
                    integer |= (uint)((byte)stream.ReadByte()) << 8;
                    integer |= (uint)((byte)stream.ReadByte());
                }
                return integer;
            }
        }


        struct TableInformation
        {
            public uint RowSize;
            public uint Offset;
            public uint Length;
        }

        struct TableHeap
        {
            public long Valid;

            public readonly TableInformation[] Tables;
            public readonly uint offsetInFile;
            public readonly uint size;

            public TableHeap(uint offsetInFile, uint size)
            {
                Valid = 0;
                Tables = new TableInformation[Mixin.TableCount];
                this.offsetInFile = offsetInFile;
                this.size = size;
            }

            public bool HasTable(Table table)
            {
                return (Valid & (1L << (int)table)) != 0;
            }
        }

        class StringHeap
        {
            public readonly uint offsetInFile;
            public readonly uint size;

            public StringHeap(uint offsetInFile, uint size)
            {
                this.offsetInFile = offsetInFile;
                this.size = size;
            }

            public string Read(Stream stream, uint index)
            {
                if (index == 0)
                    return string.Empty;

                if (index > size - 1)
                    return string.Empty;

                return ReadStringAt(stream, index);
            }

            protected virtual string ReadStringAt(Stream stream, uint index)
            {
                var buffer = new MemoryStream();
                stream.Position = offsetInFile + index;

                while (true)
                {
                    var current = (byte)stream.ReadByte();
                    if (current == 0)
                        break;

                    buffer.WriteByte(current);
                }

                return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
            }
        }


        struct BlobHeap
        {
            public readonly uint offsetInFile;
            public readonly uint size;

            public BlobHeap(uint offsetInFile, uint size)
            {
                this.offsetInFile = offsetInFile;
                this.size = size;
            }

            public byte[] Read(Stream stream, uint index)
            {
                if (index == 0 || index > this.size - 1)
                    return new byte[0];

                stream.Position = offsetInFile + index;
                int length = (int)Mixin.ReadCompressedUInt32(stream);
                //4736 - 55429 - 50944 + 4484
                //if (length > size - stream.Position - offsetInFile + index)
                //    return new byte[0];

                var buffer = new byte[length];

                stream.Read(buffer, 0, length);

                return buffer;
            }
            /*
            public void GetView(uint signature, out byte[] buffer, out int index, out int length)
            {
                if (signature == 0 || signature > data.Length - 1)
                {
                    buffer = null;
                    index = length = 0;
                    return;
                }

                buffer = data;

                index = (int)signature;
                length = (int)Mixin.ReadCompressedUInt32(buffer, ref index);
            }*/
        }

        sealed class Image
        {
            public Section[] Sections;

            public Section MetadataSection;

            public StringHeap StringHeap;
            public BlobHeap BlobHeap;
            public TableHeap TableHeap;

            public uint ResolveVirtualAddress(RVA rva)
            {
                var section = GetSectionAtVirtualAddress(rva);
                if (section == null)
                    throw new ArgumentOutOfRangeException();

                return rva + section.Value.PointerToRawData - section.Value.VirtualAddress;
            }

            public Section? GetSectionAtVirtualAddress(RVA rva)
            {
                var sections = this.Sections;
                for (int i = 0; i < sections.Length; i++)
                {
                    var section = sections[i];
                    if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
                        return section;
                }

                return null;
            }

            public int GetTableLength(Table table)
            {
                return (int)TableHeap.Tables[(int)table].Length;
            }

            public int GetTableIndexSize(Table table)
            {
                return GetTableLength(table) < 65536 ? 2 : 4;
            }

            readonly int[] coded_index_sizes = new int[14];

            public int GetCodedIndexSize(CodedIndex coded_index)
            {
                var size = coded_index_sizes[(int)coded_index];
                if (size != 0)
                    return size;

                return coded_index_sizes[(int)coded_index] = GetCodedIndexSize(coded_index, GetTableLength);
            }

            public static int GetCodedIndexSize(CodedIndex self, Func<Table, int> counter)
            {
                int bits;
                Table[] tables;

                switch (self)
                {
                    case CodedIndex.TypeDefOrRef:
                        bits = 2;
                        tables = new[] { Table.TypeDef, Table.TypeRef, Table.TypeSpec };
                        break;
                    case CodedIndex.HasConstant:
                        bits = 2;
                        tables = new[] { Table.Field, Table.Param, Table.Property };
                        break;
                    case CodedIndex.HasCustomAttribute:
                        bits = 5;
                        tables = new[] {
                    Table.Method, Table.Field, Table.TypeRef, Table.TypeDef, Table.Param, Table.InterfaceImpl, Table.MemberRef,
                    Table.Module, Table.DeclSecurity, Table.Property, Table.Event, Table.StandAloneSig, Table.ModuleRef,
                    Table.TypeSpec, Table.Assembly, Table.AssemblyRef, Table.File, Table.ExportedType,
                    Table.ManifestResource, Table.GenericParam, Table.GenericParamConstraint, Table.MethodSpec,
                };
                        break;
                    case CodedIndex.HasFieldMarshal:
                        bits = 1;
                        tables = new[] { Table.Field, Table.Param };
                        break;
                    case CodedIndex.HasDeclSecurity:
                        bits = 2;
                        tables = new[] { Table.TypeDef, Table.Method, Table.Assembly };
                        break;
                    case CodedIndex.MemberRefParent:
                        bits = 3;
                        tables = new[] { Table.TypeDef, Table.TypeRef, Table.ModuleRef, Table.Method, Table.TypeSpec };
                        break;
                    case CodedIndex.HasSemantics:
                        bits = 1;
                        tables = new[] { Table.Event, Table.Property };
                        break;
                    case CodedIndex.MethodDefOrRef:
                        bits = 1;
                        tables = new[] { Table.Method, Table.MemberRef };
                        break;
                    case CodedIndex.MemberForwarded:
                        bits = 1;
                        tables = new[] { Table.Field, Table.Method };
                        break;
                    case CodedIndex.CustomAttributeType:
                        bits = 3;
                        tables = new[] { Table.Method, Table.MemberRef };
                        break;
                    case CodedIndex.ResolutionScope:
                        bits = 2;
                        tables = new[] { Table.Module, Table.ModuleRef, Table.AssemblyRef, Table.TypeRef };
                        break;
                    default:
                        throw new ArgumentException();
                }

                int max = 0;

                for (int i = 0; i < tables.Length; i++)
                {
                    max = System.Math.Max(counter(tables[i]), max);
                }

                return max < (1 << (16 - bits)) ? 2 : 4;
            }
        }
    }
}