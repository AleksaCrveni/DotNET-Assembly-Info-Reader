using System;
using System.Collections.Generic;
using System.Text;

namespace Reader
{
  /// <summary>
  /// Simple SB wrapper, not focused on performance
  /// </summary>
  public class Logger
  {
    public StringBuilder _buffer;
    public Logger()
    {
      _buffer = new StringBuilder();
    }
    public void LogError(string log)
    {
      _buffer.Append("[ERROR]: ");
      Log(log); 
    }
    public void LogInfo(string log)
    {
      _buffer.Append("[INFO]: ");
      Log(log);
    }

    public void Log(string log)
    {
      _buffer.Append(log);
      _buffer.Append('\n');
    }

    public override string ToString() => _buffer.ToString();
  }
}
