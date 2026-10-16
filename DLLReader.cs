using Reader.Data;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text;

namespace Reader
{
  /// <summary>
  /// We will only dispose stream ourself if we create it! Do NOT dispose caller stream
  /// </summary>
  public class DLLReader
  {
    public Stream _stream;
    public Logger _logger;
    private bool IsFileStream = false;

    public DLLReader(Stream s)
    {
      _stream = s;
      _logger = new Logger();
    }

    public DLLReader(string path)
    {
      _stream = File.OpenRead(path);
      IsFileStream = true;
      _logger = new Logger();
    }

    public DLL_File? Parse(out bool valid)
    {
      valid = false;
      try
      {
        DLL_File file = new DLL_File();

        if (!ParseMSDOSHeader(file)) return null;

        valid = true;
        return file;   
      }
      catch (IndexOutOfRangeException e)
      {
        _logger.LogError("Invalid DLL. Unexpected EOF!");
        return null;
      }
      catch (Exception e)
      {
        _logger.LogError("Unexpected error during parsing. DLL may be invalid!");
        return null;
      }
      finally
      {
        if (IsFileStream)
          _stream.Close(); // this calls dispose in case of FileStream
      }
    }

    private bool ParseMSDOSHeader(DLL_File file)
    {
      Span<byte> buffer = stackalloc byte[128];
      int bytesRead = _stream.Read(buffer);
      if (bytesRead != buffer.Length)
      {
        _logger.LogError("MS-DOS Header is invalid! Size is less than 128 bytes!");
        return false;
      }

      //if (!Validator.ValidateMSDOSHeader(ref buffer, _logger)) return false;

      file.lfanew = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(60, 4));
      return true;
    }  

    private bool ParsePEFileHeader(DLL_File file)
    {
      // 20 PE Header + MAX OptionalHeader + padding to 256
      // technically we could just overwrite PE Header data when we are done with it, but still i think its fine
      Span<byte> buffer = stackalloc byte[256];

      _stream.Position = file.lfanew;
      int bytesRead = _stream.Read(buffer);
      if (bytesRead != buffer.Length)
      {
        _logger.LogError("PEHeader too short!");
        return false;
      }

      ParserHelper p = new ParserHelper(buffer);
      PE_FileHeader header = new PE_FileHeader();

      header.Signature            = p.ReadUInt();
      
      header.Machine              = p.ReadUShort();
      header.NumOfSections        = p.ReadUShort();
      header.CreatedAt            = DateTimeOffset.FromUnixTimeSeconds((long)p.ReadULong()).UtcDateTime;
      header.PointerToSymbolTable = p.ReadUInt();
      header.NumberOfSymbols      = p.ReadUInt();
      header.OptionalHeaderSize   = p.ReadUShort();
      header.Characteristics      = (PE_CHARACTERISTICS) p.ReadUShort();

      //if (!Validator.ValidatePEFileHeader(header, _logger)) return false;

      file.PEHeader = header;
      // since we may read ahead of our current table/data, we want to make sure we are put on end of it after we process size fields
      // 22 is size of PE FileEHeader  + 4 byte Signature PE\0\0
      _stream.Position = file.lfanew + 24 + header.OptionalHeaderSize;
      if (header.OptionalHeaderSize == 0) return true;

      PE_OptionalHeader oHeader = new PE_OptionalHeader();
      //II.25.2.3
      if (header.OptionalHeaderSize > 0)
      {
        if (!ParsePEFileHeaderStandardFields(oHeader, ref p)) return false;
      }
      if (header.OptionalHeaderSize > 28)
      {
        if (!ParsePEFileHeaderNTSpecificFields(oHeader, ref p)) return false;
      }
      if (header.OptionalHeaderSize > 96)
      {
        if (!ParsePEFileDataDirectories(oHeader, ref p)) return false;
      }

      file.PEHeader.OptionalHeader = oHeader;
      return true;
    }

    private bool ParsePEFileHeaderStandardFields(PE_OptionalHeader header, ref ParserHelper p)
    {
      PE_StandardFields fields = new PE_StandardFields();

      fields.Magic               = p.ReadUShort();
      fields.LMajor              = p.ReadByte();
      fields.LMinor              = p.ReadByte();
      fields.CodeSize            = p.ReadUInt();
      fields.InitializedDataSize = p.ReadUInt();
      fields.UnitializedDataSize = p.ReadUInt();
      fields.RVAEntryPoint       = p.ReadUInt();
      fields.BaseOFCode          = p.ReadUInt();
      fields.BaseOFData          = p.ReadUInt();

      //if (!Validator.ValidatePEHeaderStandardFields(fields, _logger)) return false;

      header.StandardFields = fields;
      return true;
    }

    private bool ParsePEFileHeaderNTSpecificFields(PE_OptionalHeader header, ref ParserHelper p)
    {
      PE_NTSpecificFields fields = new PE_NTSpecificFields();

      fields.ImageBase               = p.ReadUInt();
      fields.SectionAlignment        = p.ReadUInt();
      fields.FileAlignment           = p.ReadUInt();
      fields.OSMajor                 = p.ReadUShort();
      fields.OSMinor                 = p.ReadUShort();
      fields.UserMajor               = p.ReadUShort();
      fields.UserMinor               = p.ReadUShort();
      fields.SubSysMajor             = p.ReadUShort();
      fields.SubSysMinor             = p.ReadUShort();
                                       p.SkipNextN(4); // reserved
      fields.ImageSize               = p.ReadUInt();
      fields.HeaderSize              = p.ReadUInt();
      fields.FileChecksum            = p.ReadUInt();
      fields.SubSystem               = p.ReadUShort();
      fields.DLLFlags                = p.ReadUShort();
      fields.StackReserveSize        = p.ReadUInt();
      fields.StackCommitSize         = p.ReadUInt();
      fields.HeapReserveSize         = p.ReadUInt();
      fields.HeapCommitSize          = p.ReadUInt();
      fields.LoaderFlags             = p.ReadUInt();
      fields.NumberOfDataDirectories = p.ReadUInt();

      header.NTSpecificFields = fields;
      return true;
    }

    private bool ParsePEFileDataDirectories(PE_OptionalHeader header, ref ParserHelper p)
    {
      PE_DataDirectories fields = new PE_DataDirectories();

      fields.ExportTableOffset                = p.ReadULong();
      fields.ImportTableOffset                = p.ReadULong();
      fields.ResourceTableOffset              = p.ReadULong();
      fields.ExceptionTableOffset             = p.ReadULong();
      fields.CertificateTableOffset           = p.ReadULong();
      fields.BaseRelocationTableOffset        = p.ReadULong();
      fields.DebugTableOffset                 = p.ReadULong();
      fields.CopyrightTableOffset             = p.ReadULong();
      fields.GlobalPtrTableOffset             = p.ReadULong();
      fields.TLSTableOffset                   = p.ReadULong();
      fields.LoadConfigTableOffset            = p.ReadULong();
      fields.BoundImport                      = p.ReadULong();
      fields.IATTableOffset                   = p.ReadULong();
      fields.DelayImportDescriptorTableOffset = p.ReadULong();
      fields.CLIHeaderTableOffset             = p.ReadULong();
                                                p.SkipNextN(8);

      header.DataDirectories = fields;
      return true;
    }


    public string GetLogs() => _logger.ToString();
  }
}
