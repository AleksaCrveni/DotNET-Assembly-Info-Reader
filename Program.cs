using Reader;

string path = @"W:\PDFToImageConverter\Converter\bin\Debug\net11.0\Converter.dll";
FileStream fs = File.OpenRead(path);
Logger l = new Logger();
bool valid = Validator.ValidatePEHeaders(fs, l);
Console.Write(l.ToString());