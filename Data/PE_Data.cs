using System;
using System.Collections.Generic;
using System.Text;

namespace Reader.Data
{
  public class PE_FileHeader
  {
    public uint Signature;
    /// <summary>
    /// Always 0x14c.
    /// </summary>
    public ushort Machine;

    /// <summary>
    /// Number of sections; indicates size of the Section Table,  which immediately follows the headers.
    /// </summary>
    public ushort NumOfSections;

    /// <summary>
    /// Time and date the file was created in seconds since  January 1st 1970 00:00:00 or 0.
    /// </summary>
    public DateTime CreatedAt;

    /// <summary>
    /// 0
    /// </summary>
    public uint PointerToSymbolTable;

    /// <summary>
    /// 0
    /// </summary>
    public uint NumberOfSymbols;

    /// <summary>
    /// Size of the optional header,
    /// </summary>
    public ushort OptionalHeaderSize;

    /// <summary>
    /// Flags indicating attributes of the file,
    /// </summary>
    public PE_CHARACTERISTICS Characteristics;
    public PE_OptionalHeader? OptionalHeader;
  }
  public class PE_OptionalHeader
  {
    /// <summary>
    /// These define general properties of the PE file
    /// </summary>
    public PE_StandardFields? StandardFields;
    /// <summary>
    /// These include additional fields to support specific features of  Windows
    /// </summary>
    public PE_NTSpecificFields? NTSpecificFields;
    /// <summary>
    /// These fields are address/size pairs for special tables, found in  the image file (for example, Import Table and Export Table).
    /// </summary>
    public PE_DataDirectories? DataDirectories;
  }

  /// <summary>
  /// These fields are required for all PE files and contain the following information: 
  /// </summary>
  public class PE_StandardFields
  {
    public ushort Magic;
    public byte LMajor;
    public byte LMinor;
    /// <summary>
    /// Size of the code (text) section, or the sum of all code sections  if there are multiple sections.
    /// </summary>
    public uint CodeSize;
    /// <summary>
    /// Size of the initialized data section, or the sum of all such  sections if there are multiple data sections.
    /// </summary>
    public uint InitializedDataSize;
    /// <summary>
    /// Size of the uninitialized data section, or the sum of all such  sections if there are multiple unitinitalized data sections.
    /// </summary>
    public uint UnitializedDataSize;
    /// <summary>
    /// RVA of entry point , needs to point to bytes 0xFF 0x25  followed by the RVA in a section marked execute/read for EXEs or 0 for DLLs.
    /// RVA - Relative Virtual Address
    /// </summary>
    public uint RVAEntryPoint;
    /// <summary>
    /// RVA of the code section. (This is a hint to the loader.)
    /// </summary>
    public uint BaseOFCode;
    /// <summary>
    /// RVA of the data section. (This is a hint to the loader.)
    /// </summary>
    public uint BaseOFData;

  }

  public class PE_NTSpecificFields
  {
    /// <summary>
    /// Shall be a multiple of 0x10000
    /// </summary>
    public uint ImageBase;
    /// <summary>
    /// Shall be greater than File Alignment.
    /// </summary>
    public uint SectionAlignment;
    /// <summary>
    /// Should be 0x200
    /// </summary>
    public uint FileAlignment;
    /// <summary>
    /// 5
    /// </summary>
    public ushort OSMajor;
    /// <summary>
    /// 0
    /// </summary>
    public ushort OSMinor;
    /// <summary>
    /// 0
    /// </summary>
    public ushort UserMajor;
    /// <summary>
    /// 0
    /// </summary>
    public ushort UserMinor;
    /// <summary>
    /// 5
    /// </summary>
    public ushort SubSysMajor;
    /// <summary>
    /// 0
    /// </summary>
    public ushort SubSysMinor;
    /// <summary>
    /// 0
    /// </summary>
    public uint Reserved;
    /// <summary>
    /// Size, in bytes, of image, including all headers and padding;  shall be a multiple of Section Alignment.
    /// </summary>
    public uint ImageSize;
    /// <summary>
    /// Combined size of MS-DOS Header, PE Header, PE Optional  Header and padding; shall be a multiple of the file alignment.
    /// </summary>
    public uint HeaderSize;
    /// <summary>
    /// 0
    /// </summary>
    public uint FileChecksum;
    /// <summary>
    /// Subsystem required to run this image. Shall be either  IMAGE_SUBSYSTEM_WINDOWS_CUI (0x3) or IMAGE_SUBSYSTEM_WINDOWS_GUI (0x2).
    /// </summary>
    /// 
    public ushort SubSystem;
    /// <summary>
    /// Bits 0x100f shall be zero.
    /// </summary>
    public ushort DLLFlags;
    /// <summary>
    /// Should be 0x100000 (1Mb)
    /// </summary>
    public uint StackReserveSize;
    /// <summary>
    /// Should be 0x1000 (4Kb)
    /// </summary>
    public uint StackCommitSize;
    /// <summary>
    /// Should be 0x100000 (1Mb)
    /// </summary>
    public uint HeapReserveSize;
    /// <summary>
    /// Should be 0x1000 (4Kb)
    /// </summary>
    public uint HeapCommitSize;
    /// <summary>
    /// 0
    /// </summary>
    public uint LoaderFlags;
    /// <summary>
    /// 0x10
    /// </summary>
    public uint NumberOfDataDirectories;

  }

  public class PE_DataDirectories
  {
    /// <summary>
    /// 0
    /// </summary>
    public ulong ExportTableOffset;
    /// <summary>
    /// RVA and Size of Import Table,
    /// </summary>
    public ulong ImportTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong ResourceTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong ExceptionTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong CertificateTableOffset;
    /// <summary>
    /// Relocation Table set to 0 if unused
    /// </summary>
    public ulong BaseRelocationTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong DebugTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong CopyrightTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong GlobalPtrTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong TLSTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong LoadConfigTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong BoundImport;
    /// <summary>
    /// RVA and Size of Import Addres Table
    /// </summary>
    public ulong IATTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong DelayImportDescriptorTableOffset;
    /// <summary>
    /// CLI Header with directories for runtime data,
    /// </summary>
    public ulong CLIHeaderTableOffset;
    /// <summary>
    /// 0
    /// </summary>
    public ulong Reserved;

  }



}
