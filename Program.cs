using Reader;
using Reader.Data;

string path = @"W:\PDFToImageConverter\Converter\bin\Debug\net11.0\Converter.dll";
DLLReader r = new DLLReader(path);
DLL_File dll = r.Parse(out bool valid);
if (!valid)
  Console.Write(r.GetLogs());
else
  Console.WriteLine("Valid parsing!");