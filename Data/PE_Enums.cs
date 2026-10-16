using System;
using System.Collections.Generic;
using System.Text;

namespace Reader.Data
{
  [Flags]
  public enum PE_CHARACTERISTICS
  {
    IMAGE_FILE_RELOCS_STRIPPED  = 1 << 0,
    IMAGE_FILE_EXECUTABLE_IMAGE = 1 << 1,
    IMAGE_FILE_32BIT_MACHINE    = 1 << 8,
    IMAGE_FILE_DLL              = 1 << 13,
    IMPL_SPECIFIC_1             = 1 << 4,
    IMPL_SPECIFIC_2             = 1 << 5,
    IMPL_SPECIFIC_3             = 1 << 10,
    IMPL_SPECIFIC_4             = 1 << 11
  }


  public enum PE_CONSTANTS : ushort
  {
    SIG_VALIDATION = 17744,
    MACHINE_VALIDATION = 0x14c,
    MAGIC_VALIDATION = 0x10B
  }

}
