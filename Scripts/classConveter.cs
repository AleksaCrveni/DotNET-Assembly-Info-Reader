using System.Text;

string cName = "ClassName";
if (args.Length > 0)
  cName = args[0].ToString();
string[] lines = File.ReadAllLines("in.txt");
StringBuilder sb = new StringBuilder();
sb.Append("public class ");
sb.Append(cName);
sb.Append('\n');
sb.Append('{');
sb.Append('\n');
foreach (string line in lines)
{
  string[] data = line.Split(' ');
  string size = data[1].Trim();
  string field = data[2].Trim();
  string desc = line.AsSpan().Slice(line.IndexOf(field) + field.Length).ToString();
  sb.Append("  /// <summary>\n");
  sb.AppendFormat("  /// {0}\n", desc);
  sb.Append("  /// </summary>\n");
  string type = size switch
  {
    "1" => "byte",
    "2" => "ushort",
    "4" => "uint",
    "8" => "ulong",
    _   => "type"
  };
  sb.AppendFormat("  public {0} {1};\n", type, field);
}

sb.Append('}');

File.WriteAllText("out.txt", sb.ToString());