using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
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
    
    
    public static bool ValidatePEHeaders(Stream s, Logger logger)
    {
      (bool valid, uint lfanew) MSDOSHeaderValidationResult = ValidateMSDOSHeader(s, logger);
      if (!MSDOSHeaderValidationResult.valid)
        return false;
      uint lfanew = MSDOSHeaderValidationResult.lfanew;

      logger.LogInfo("PE Headers are valid!");
      return true;
    }

    public static (bool valid, uint lfanew) ValidateMSDOSHeader(Stream s, Logger logger)
    {
      Span<byte> buffer = stackalloc byte[128];
      int bytesRead = s.Read(buffer);
      if (bytesRead != buffer.Length)
      {
        logger.LogError("MS-DOS Header is invalid! Size is less than 128 bytes!");
        return (false, 0);
      }

      bool isP1Same = buffer.Slice(0, 56).SequenceEqual(MSDOSHeaderP1.AsSpan());
      bool isP2Same = buffer.Slice(63).SequenceEqual(MSDOSHeaderP2.AsSpan());

      if (!isP1Same)
      {
        logger.LogError("MS-DOS Header is invalid! First 56 bytes do not match!");
        return (false, 0);
      }

      if (isP2Same)
      {
        logger.LogError("MS-DOS Header is invalid! Last 64 bytes do not match!");
        return (false, 0);
      }

      uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(56, 4));
      if (lfanew != 0)
      {
        logger.LogError("MS-DOS Header is invalid! 56-60 byte range does not match!");
        return (false, 0);
      }

      lfanew = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(60, 4));
      if (lfanew < 128)
      {
        logger.LogError("MS-DOS Header is invalid! Invalid lfanew offset!");
        return (false, 0);
      }

      return (true, lfanew);
    }
  }
}
