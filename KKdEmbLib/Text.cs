using System.Text;

namespace KKdEmbLib
{
    public static class Text
    {
        public readonly static Encoding ShiftJIS = Encoding.GetEncoding(932);

        public static string ToASCII(this byte[] Array) => Encoding.ASCII.GetString(Array ?? new byte[0]);
        public static byte[] ToASCII(this string Data ) => Encoding.ASCII.GetBytes (Data  ?? ""         );
        public static byte[] ToASCII(this char[] Data ) => Encoding.ASCII.GetBytes (Data  ?? new char[0]);
        public static string ToSJIS (this byte[] Array) =>       ShiftJIS.GetString(Array ?? new byte[0]);
        public static byte[] ToSJIS (this string Data ) =>       ShiftJIS.GetBytes (Data  ?? ""         );
        public static byte[] ToSJIS (this char[] Data ) =>       ShiftJIS.GetBytes (Data  ?? new char[0]);
        public static string ToUTF8 (this byte[] Array) => Encoding.UTF8 .GetString(Array ?? new byte[0]);
        public static byte[] ToUTF8 (this string Data ) => Encoding.UTF8 .GetBytes (Data  ?? ""         );
        public static byte[] ToUTF8 (this char[] Data ) => Encoding.UTF8 .GetBytes (Data  ?? new char[0]);
    }
}
