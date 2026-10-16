using Reader.Data;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Reader
{


  public static class Validator
  {
    public static readonly byte[] MSDOSHeaderP1 = [
      0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
      0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    public static readonly byte[] MSDOSHeaderP2 = [
      0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
      0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
      0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
      0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
      0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
      0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
      0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
      0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
     ];
    
    public static bool ValidateMSDOSHeader(ref Span<byte> buffer, Logger logger)
    {
      bool isP1Same = buffer.Slice(0, 56).SequenceEqual(MSDOSHeaderP1.AsSpan());
      bool isP2Same = buffer.Slice(63).SequenceEqual(MSDOSHeaderP2.AsSpan());

      if (!isP1Same)
      {
        logger.LogError("MS-DOS Header is invalid! First 56 bytes do not match!");
        return false;
      }

      if (isP2Same)
      {
        logger.LogError("MS-DOS Header is invalid! Last 64 bytes do not match!");
        return false;
      }

      uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(56, 4));
      if (lfanew != 0)
      {
        logger.LogError("MS-DOS Header is invalid! 56-60 byte range does not match!");
        return false;
      }

      lfanew = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(60, 4));
      if (lfanew < 128)
      {
        logger.LogError("MS-DOS Header is invalid! Invalid lfanew offset!");
        return false;
      }


      return true;
    }

    public static bool ValidatePEFileHeader(PE_FileHeader header, Logger logger)
    {
      if (header.Signature != (ushort)PE_CONSTANTS.SIG_VALIDATION)
      {
        logger.LogError("PE Header is invalid. Invalid signature, expected PE");
        return false;
      }

      if (header.Machine != (ushort)PE_CONSTANTS.MACHINE_VALIDATION)
      {
        logger.LogError("PE Header is invalid. Invalid Machine, expected 0x14c");
        return false;
      }

      if (header.PointerToSymbolTable != 0)
      {
        logger.LogError("PE Header is invalid. Pointer to symbol table offset invalid, expected 0x14c");
        return false;
      }

      if (header.NumberOfSymbols != 0)
      {
        logger.LogError("PE Header is invalid. Invalid Number of Symbols, expected 0");
        return false;
      }

      // check min max range 
      // ref II.25.2.3 PE optional header
      if (header.OptionalHeaderSize < 0 || header.OptionalHeaderSize > 224)
      {
        logger.LogError("PE Header is invalid. Invalid optional header size");
        return false;
      }

      if (header.Characteristics.HasFlag(PE_CHARACTERISTICS.IMAGE_FILE_RELOCS_STRIPPED) != false)
      {
        logger.LogError("PE Header is invalid. IMAGE_FILE_RELOCS_STRIPPED flag is not 0");
        return false;
      }

      if (header.Characteristics.HasFlag(PE_CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE) != true)
      {
        logger.LogError("PE Header is invalid. IMAGE_FILE_EXECUTABLE_IMAGE flag is not 1");
        return false;
      }
      // validate 32bit machine later since it depends on CLI Header data
      if (header.Characteristics.HasFlag(PE_CHARACTERISTICS.IMAGE_FILE_DLL) != true)
      {
        logger.LogError("PE Header is invalid. IMAGE_FILE_DLL flag is not 1 (this is not DLL?)");
        return false;
      }

      // this bellow par tis to make sure that all other unusued bits are 0 per spec
      PE_CHARACTERISTICS validCharactersitics =
        PE_CHARACTERISTICS.IMAGE_FILE_DLL | PE_CHARACTERISTICS.IMAGE_FILE_EXECUTABLE_IMAGE | PE_CHARACTERISTICS.IMAGE_FILE_DLL |
        header.Characteristics & PE_CHARACTERISTICS.IMPL_SPECIFIC_1 | header.Characteristics & PE_CHARACTERISTICS.IMPL_SPECIFIC_2 |
        header.Characteristics & PE_CHARACTERISTICS.IMPL_SPECIFIC_3 | header.Characteristics & PE_CHARACTERISTICS.IMPL_SPECIFIC_4;

      if (validCharactersitics != header.Characteristics)
      {
        logger.LogError("PE Header is invalid. Invalid Characteristics flags values!");
        return false;
      }

      return true;
    }

    public static bool ValidatePEHeaderStandardFields(PE_StandardFields header, Logger logger)
    {
      if (header.Magic != (ushort)PE_CONSTANTS.MAGIC_VALIDATION)
      {

      }

      // spec not up to date? my dll has value 48
      //if (header.LMajor != 6)
      //{

      //}

      if (header.LMinor != 0)
      {

      }

      // this is 
      if (header.RVAEntryPoint != 0)
      {

      }


      return true;
    }
  }
}
