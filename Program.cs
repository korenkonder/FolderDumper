using System;
using KKdEmbLib;
using KKdEmbLib.IO;

namespace FolderDumper
{
    public class Program
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        public static void Main(string[] args)
        {
            SetProcessDPIAware();

            Console. InputEncoding = System.Text.Encoding.Unicode;
            Console.OutputEncoding = System.Text.Encoding.Unicode;
            Console.Title = "FolderDumper";

            Version ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            if (args == null || args.Length < 1) goto Help;

            string i = null, o = null, ik = null, ok = null;
            string[] il = null; string[] ikl = null; bool[] kfl = null;
            int arl = args.Length;
            int n = 0;
            string arg;
            string last = "";
            bool[] has = new bool[12];
            for (int j = 0; j < 12; j++) has[j] = false;

            for (int j = 0; j < arl; j++)
            {
                arg = args[j];
                     if (!has[ 0] && last == "-i") { has[0] = true; i = arg; }
                else if (!has[ 1] && last == "-o") { has[1] = true; o = arg; }
                else if (!has[ 6] &&  arg == "-r") has[ 6] = true;
                else if (!has[ 7] &&  arg == "-h") has[ 7] = true;
                else if (!has[ 8] &&  arg == "-v") has[ 8] = true;
                else if (!has[ 9] &&  arg == "-d") has[ 9] = true;
                else if (!has[11] &&  arg == "-s") has[11] = true;
                else if (!has[10] && last == "-n")
                {
                    if (!int.TryParse(arg, out n)) { last = arg; continue; }

                    int l = 0;
                    il = new string[n]; ikl = new string[n]; kfl = new bool[n];
                    bool[] a = new bool[3];
                    a[0] = a[1] = a[2] = false;
                    for (int k = 0; k < arl; k++)
                    {
                             if (         args[k] ==  $"-i{l}" && k + 1 < arl) {  il[l] = args[++k]; a[0] = true; }
                        else if (!a[2] && args[k] ==  $"-k{l}" && k + 1 < arl) { ikl[l] = args[++k]; a[1] = true; }
                        else if (!a[1] && args[k] == $"-kf{l}" && k + 1 < arl) { ikl[l] = args[++k]; a[2] = true; }

                        if (a[0] && (a[1] || a[2]))
                        {
                            kfl[l] = a[2]; l++; a[0] = a[1] = a[2] = false;
                            if (l == n) { has[10] = l == n; break; }
                        }
                    }
                    if (!has[10]) { il = ikl = null; kfl = null; }
                }
                else if (!has[2] || !has[3])
                {
                         if (!has[2] && last == "-ik" ) { has[2] = true; ik = arg; }
                    else if (!has[2] && last == "-ikf") { has[2] = has[4] = true; ik = arg; }
                    else if (!has[3] && last == "-ok" ) { has[3] = true; ok = arg; }
                    else if (!has[3] && last == "-okf") { has[3] = has[5] = true; ok = arg; }
                    else if (last == "-k" ) { has[2] = has[3] = true; ik = ok = arg; }
                    else if (last == "-kf") { has[2] = has[3] = has[4] = has[5] = true; ik = ok = arg; }
                }
                last = arg;
            }

            if (has[8]) { Console.WriteLine($"FolderDumper v{ver}"); return; }
            else if (!has[0] || has[7]) goto Help;

            if (!has[1] && (o = Path.GetFileName(i)) == "")
                o = Path.GetFileNameWithoutExtension(i.Replace(":", "_drive").Replace("\\", ""));

            if (Directory.Exists(i))
            {
                FilePacker fp;
                if (has[3])
                {
                    if (!has[5])
                    {
                        fp = new FilePacker(ok);
                        File.WriteAllBytes(getPath(o), fp.Key);
                    }
                    else if (getFilePacker(ok, out fp)) return;
                }
                else if (getKey(o, out fp)) return;

                fp.Pack(i, o);
                fp.Dispose();
            }
            else if (File.Exists(i))
            {
                FilePacker fp;
                if (!has[2]) { Console.Write("Enter password: "); ik = Console.ReadLine(); fp = new FilePacker(ik); }
                else if (getFilePacker(ik, out fp)) return;

                if (has[10])
                {
                    FilePacker fp1;
                    if (has[3])
                    {
                        if (!has[5])
                        {
                            fp1 = new FilePacker(ok);
                            File.WriteAllBytes(getPath(o), fp1.Key);
                        }
                        else if (getFilePacker(ok, out fp1)) return;
                    }
                    else if (getKey(o, out fp1)) return;
                    byte[] key = fp1.Key;

                    byte[][] keys = new byte[n][];
                    FilePacker fp2;
                    for (int j = 0; j < n; j++)
                    {
                        if (!kfl[j])
                        {
                            fp2 = new FilePacker(ok);
                            File.WriteAllBytes(getPath(il[j]), fp2.Key);
                        }
                        else if (getFilePacker(ikl[j], out fp2)) return;

                        keys[j] = fp2.Key;
                        fp2.Dispose();
                    }
                    if (has[9]) fp.Differentiate(i, key, il, keys);
                    else        fp.Unpack    (i, o, key, il, keys, has[11]);
                    fp.Dispose();
                }
                else if (has[6])
                {
                    FilePacker fp2;
                    if (has[3])
                    {
                        if (!has[5])
                        {
                            fp2 = new FilePacker(ok);
                            File.WriteAllBytes(getPath(o), fp2.Key);
                        }
                        else if (getFilePacker(ok, out fp2)) return;
                    }
                    else if (getKey(o, out fp2)) return;

                    byte[] key2 = fp2.Key;
                    fp2.Dispose();

                    if (key2 == null) return;
                    if (has[1]) fp.Repack(i, o, key2);
                    else        fp.Repack(i,    key2);
                }
                else fp.Unpack(i, o, has[11]);
                fp.Dispose();
            }
            else Console.WriteLine($"Location \"{i}\" doesn't exist");
            return;

        Help:
            Console.WriteLine($"FolderDumper v{ver}");
            Console.WriteLine($"Usage: FolderDumper [-iokfrhvb]");
            Console.WriteLine($"    -i          Input file/folder");
            Console.WriteLine($"    -o          Output file/folder");
            Console.WriteLine($"    -ik         Input password");
            Console.WriteLine($"    -ikf        Input key file");
            Console.WriteLine($"    -ok         Output password");
            Console.WriteLine($"    -okf        Output key file");
            Console.WriteLine($"    -k          Input/Output password");
            Console.WriteLine($"    -kf         Input/Output key file");
            Console.WriteLine($"    -s          Show Root Folder if it was hidden");
            Console.WriteLine($"    -r          Repack file");
            Console.WriteLine($"    -v          Print version");
            Console.WriteLine($"    -h          Print this help");
            Console.WriteLine($"    -d          Build differental file");
            Console.WriteLine($"    -n          Parent count");
            Console.WriteLine($"    -i[0-n]     Input parent file");
            Console.WriteLine($"    -k[0-n]     Input parent password");
            Console.WriteLine($"    -kf[0-n]    Input parent key file");

            static bool getKey(string o, out FilePacker fp)
            {
                fp = default;
                Console.Write("Enter password: "); string temp = Console.ReadLine();
                Console.Write("Confirm password: "); string password = Console.ReadLine();
                if (password != temp) { Console.WriteLine("Passwords doesn't match"); return true; }

                fp = new FilePacker(password);
                File.WriteAllBytes(getPath(o), fp.Key);
                return false;
            }

            static bool getFilePacker(string k, out FilePacker fp)
            {
                fp = default;
                if (File.Exists(k))
                {
                    byte[] key = File.ReadAllBytes(k);
                    if (key == null || key.Length != 64)
                    { Console.WriteLine($"File \"{k}\" has invalid length\nShould be 64 bytes"); return true; }
                    fp = new FilePacker(key);
                }
                else
                    fp = new FilePacker(k);
                return false;
            }

            static string getPath(string file) =>
                file.EndsWith(".kkfp") ? file.EndsWith(".kkfpd") ?
                file.Replace(".kkfpd", ".kkfpk") : (file + ".kkfpk") : (file + "k");
        }
    }
}
