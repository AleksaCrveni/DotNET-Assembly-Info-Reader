using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Reader
{
  /// <summary>
  /// No bounds checking since we would have to throw exception from here anyways so its the same in the end
  /// LittleEndian
  /// </summary>
  public ref struct ParserHelper
  {
    public ReadOnlySpan<byte> _buffer;
    public int _pos;

    public ParserHelper(Span<byte> buffer)
    {
      _buffer = buffer;
    }
    public ParserHelper(ReadOnlySpan<byte> buffer)
    {
      _buffer = buffer;
    }

    public ParserHelper(byte[] buffer)
    {
      _buffer = buffer;
    }

    public byte ReadByte() => _buffer[_pos++];
    public void SkipNextN(int n) => _pos += n;
    public ushort ReadUShort()
    {
      ushort res = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_pos, 2));
      _pos += 2;
      return res;
    }

    public uint ReadUInt()
    {
      uint res = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_pos, 4));
      _pos += 4;
      return res;
    }

    public ulong ReadULong()
    {
      ulong res = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_pos, 8));
      _pos += 8;
      return res;
    }
  }
}
