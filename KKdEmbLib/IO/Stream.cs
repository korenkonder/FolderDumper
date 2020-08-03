using System;
using MSIO = System.IO;

namespace KKdEmbLib.IO
{
    public unsafe class Stream : IDisposable
    {
        private int i, j, bitRead, bitWrite, tempBitRead, tempBitWrite, valRead, valWrite;
        private byte[] b;
        private MSIO.Stream s;

        private readonly bool canRead;
        private readonly bool canWrite;

        public bool IsBE = false;

        public  int O    { get => ( int)OI64; set => OI64 = value; }
        public uint OU32 { get => (uint)OI64; set => OI64 = value; }
        public long OI64;

        public  int L    { get => ( int)s.Length -    O; set => s.SetLength(value + O   ); }
        public uint LU32 { get => (uint)s.Length - OU32; set => s.SetLength(value + OU32); }
        public long LI64 { get =>       s.Length - OI64; set => s.SetLength(value + OI64); }

        public  int P    { get => ( int)s.Position -    O; set => s.Position = value + O   ; }
        public uint PU32 { get => (uint)s.Position - OU32; set => s.Position = value + OU32; }
        public long PI64 { get =>       s.Position - OI64; set => s.Position = value + OI64; }

        public bool CanRead    => canRead ;
        public bool CanSeek    => s.CanSeek;
        public bool CanTimeout => s.CanTimeout;
        public bool CanWrite   => s.CanWrite && canWrite;

        public string File = null;

        public Stream(MSIO.Stream output = null, bool isBE = false, bool canRead = true, bool canWrite = true)
        {
            if (output == null) output = MSIO.Stream.Null;
            OI64 = 0;
            bitRead = 8;
            valRead = valRead = bitWrite = 0;
            s = output;
            b = new byte[0x100];
            IsBE = isBE;
            this.canRead  = s.CanRead  && canRead;
            this.canWrite = s.CanWrite && canWrite;
        }

        public void C() => D(true);

        public void F() => s.Flush();

        public void SL(long length = 0) => s.SetLength(length);

        public long S(long offset, SeekOrigin origin = 0) =>
            s.Seek(offset + O, (MSIO.SeekOrigin)(int)origin);

        public long? S(long? offset, SeekOrigin origin)
        { if (offset == null) return null;
            return s.Seek((long)offset + O, (MSIO.SeekOrigin)(int)origin); }

        private bool disposed = false;
        public void D() => D(true);
        public void Dispose() => D(true);

        protected virtual void D(bool dispose)
        { CW(); if (s != MSIO.Stream.Null && !disposed) { disposed = true; s.Flush();
                s.Dispose(); } if (dispose) GC.SuppressFinalize(this); }

        public MSIO.Stream BS
        { get { s.Flush(); return s; } set { s = value; } }

        public void A(long align)
        {
            long Al = align - P % align;
            if (P % align != 0) s.Seek(P + O + Al, 0);
        }

        public void A(long align, bool setLength)
        {
            if (setLength) s.SetLength(P + O);
            long Al = align - P % align;
            if (P % align != 0) s.Seek(P + O + Al, 0);
            if (setLength) s.SetLength(P + O);
        }

        public void A(long align, bool setLength0, bool setLength1)
        {
            if (setLength0) s.SetLength(P + O);
            long Al = align - P % align;
            if (P % align != 0) s.Seek(P + Al, 0);
            if (setLength1) s.SetLength(P + O);
        }

        private void cR() { if (!canRead ) throw new Exception("Stream cannot be read!"); }
        private void cW() { if (!canWrite) throw new Exception("Stream cannot be read!"); }

        public   bool RBo () { cR(); return        s.ReadByte() != 0; }
        public  sbyte RI8 () { cR(); return (sbyte)s.ReadByte(); }
        public   byte RU8 () { cR(); return ( byte)s.ReadByte(); }
        public  short RI16() { cR(); s.Read(b, 0, 2); return b.TI16(); }
        public ushort RU16() { cR(); s.Read(b, 0, 2); return b.TU16(); }
        public    int RI32() { cR(); s.Read(b, 0, 4); return b.TI32(); }
        public   uint RU32() { cR(); s.Read(b, 0, 4); return b.TU32(); }
        public   long RI64() { cR(); s.Read(b, 0, 8); return b.TI64(); }
        public  ulong RU64() { cR(); s.Read(b, 0, 8); return b.TU64(); }
        public  float RF32() { cR(); s.Read(b, 0, 4); return b.TF32(); }
        public double RF64() { cR(); s.Read(b, 0, 8); return b.TF64(); }

        public  short RI16E() { cR(); s.Read(b, 0, 2); b.E(2, IsBE); return b.TI16(); }
        public ushort RU16E() { cR(); s.Read(b, 0, 2); b.E(2, IsBE); return b.TU16(); }
        public    int RI32E() { cR(); s.Read(b, 0, 4); b.E(4, IsBE); return b.TI32(); }
        public   uint RU32E() { cR(); s.Read(b, 0, 4); b.E(4, IsBE); return b.TU32(); }
        public   long RI64E() { cR(); s.Read(b, 0, 8); b.E(8, IsBE); return b.TI64(); }
        public  ulong RU64E() { cR(); s.Read(b, 0, 8); b.E(8, IsBE); return b.TU64(); }
        public  float RF32E() { cR(); s.Read(b, 0, 4); b.E(4, IsBE); return b.TF32(); }
        public double RF64E() { cR(); s.Read(b, 0, 8); b.E(8, IsBE); return b.TF64(); }

        public  short RI16E(bool isBE) { cR(); s.Read(b, 0, 2); b.E(2, isBE); return b.TI16(); }
        public ushort RU16E(bool isBE) { cR(); s.Read(b, 0, 2); b.E(2, isBE); return b.TU16(); }
        public    int RI32E(bool isBE) { cR(); s.Read(b, 0, 4); b.E(4, isBE); return b.TI32(); }
        public   uint RU32E(bool isBE) { cR(); s.Read(b, 0, 4); b.E(4, isBE); return b.TU32(); }
        public   long RI64E(bool isBE) { cR(); s.Read(b, 0, 8); b.E(8, isBE); return b.TI64(); }
        public  ulong RU64E(bool isBE) { cR(); s.Read(b, 0, 8); b.E(8, isBE); return b.TU64(); }
        public  float RF32E(bool isBE) { cR(); s.Read(b, 0, 4); b.E(4, isBE); return b.TF32(); }
        public double RF64E(bool isBE) { cR(); s.Read(b, 0, 8); b.E(8, isBE); return b.TF64(); }

        public void W(byte[] val                        )
        { cW(); s.Write(val ?? new byte[0],      0, val.Length); }
        public void W(byte[] val,             int Length)
        { cW(); s.Write(val ?? new byte[0],      0,     Length); }
        public void W(byte[] val, int offset, int length)
        { cW(); s.Write(val ?? new byte[0], offset,     length); }
        public void W(char[] val, bool utf8 = true) =>
            W(utf8 ? val.ToUTF8() : val.ToASCII());

        public void W(  bool val) { cW(); s.WriteByte((byte)(val ? 1 : 0)); }
        public void W( sbyte val) { cW(); s.WriteByte((byte) val); }
        public void W(  byte val) { cW(); s.WriteByte(       val); }
        public void W( short val) { cW(); b.GBy(val); s.Write(b, 0, 2); }
        public void W(ushort val) { cW(); b.GBy(val); s.Write(b, 0, 2); }
        public void W(   int val) { cW(); b.GBy(val); s.Write(b, 0, 4); }
        public void W(  uint val) { cW(); b.GBy(val); s.Write(b, 0, 4); }
        public void W(  long val) { cW(); b.GBy(val); s.Write(b, 0, 8); }
        public void W( ulong val) { cW(); b.GBy(val); s.Write(b, 0, 8); }
        public void W( float val) { cW(); b.GBy(val); s.Write(b, 0, 4); }
        public void W(double val) { cW(); b.GBy(val); s.Write(b, 0, 8); }

        public void W( sbyte? val) => W(val ?? default);
        public void W(  byte? val) => W(val ?? default);
        public void W( short? val) => W(val ?? default);
        public void W(ushort? val) => W(val ?? default);
        public void W(   int? val) => W(val ?? default);
        public void W(  uint? val) => W(val ?? default);
        public void W(  long? val) => W(val ?? default);
        public void W( ulong? val) => W(val ?? default);
        public void W( float? val) => W(val ?? default);
        public void W(double? val) => W(val ?? default);

        public void W(  char val, bool utf8 = true) =>
            W(utf8 ? val.ToString().ToUTF8() : val.ToString().ToASCII());
        public void W(string val, bool utf8 = true) =>
            W(utf8 ? val           .ToUTF8() : val           .ToASCII());

        public void WE( short val) { cW(); b.GBy(val); b.E(2, IsBE); s.Write(b, 0, 2); }
        public void WE(ushort val) { cW(); b.GBy(val); b.E(2, IsBE); s.Write(b, 0, 2); }
        public void WE(   int val) { cW(); b.GBy(val); b.E(4, IsBE); s.Write(b, 0, 4); }
        public void WE(  uint val) { cW(); b.GBy(val); b.E(4, IsBE); s.Write(b, 0, 4); }
        public void WE(  long val) { cW(); b.GBy(val); b.E(8, IsBE); s.Write(b, 0, 8); }
        public void WE( ulong val) { cW(); b.GBy(val); b.E(8, IsBE); s.Write(b, 0, 8); }
        public void WE( float val) { cW(); b.GBy(val); b.E(4, IsBE); s.Write(b, 0, 4); }
        public void WE(double val) { cW(); b.GBy(val); b.E(8, IsBE); s.Write(b, 0, 8); }

        public void WE( short val, bool isBE) { cW(); b.GBy(val); b.E(2, isBE); s.Write(b, 0, 2); }
        public void WE(ushort val, bool isBE) { cW(); b.GBy(val); b.E(2, isBE); s.Write(b, 0, 2); }
        public void WE(   int val, bool isBE) { cW(); b.GBy(val); b.E(4, isBE); s.Write(b, 0, 4); }
        public void WE(  uint val, bool isBE) { cW(); b.GBy(val); b.E(4, isBE); s.Write(b, 0, 4); }
        public void WE(  long val, bool isBE) { cW(); b.GBy(val); b.E(8, isBE); s.Write(b, 0, 8); }
        public void WE( ulong val, bool isBE) { cW(); b.GBy(val); b.E(8, isBE); s.Write(b, 0, 8); }
        public void WE( float val, bool isBE) { cW(); b.GBy(val); b.E(4, isBE); s.Write(b, 0, 4); }
        public void WE(double val, bool isBE) { cW(); b.GBy(val); b.E(8, isBE); s.Write(b, 0, 8); }

        public  int RI24 (         ) { cR(); s.Read(b, 0, 3);               return b.TI24(); }
        public uint RU24 (         ) { cR(); s.Read(b, 0, 3);               return b.TU24(); }
        public  int RI24E(         ) { cR(); s.Read(b, 0, 3); b.E(3, IsBE); return b.TI24(); }
        public uint RU24E(         ) { cR(); s.Read(b, 0, 3); b.E(3, IsBE); return b.TU24(); }
        public  int RI24E(bool isBE) { cR(); s.Read(b, 0, 3); b.E(3, isBE); return b.TI24(); }
        public uint RU24E(bool isBE) { cR(); s.Read(b, 0, 3); b.E(3, isBE); return b.TU24(); }

        public char RC(bool utf8 = true)
        { cR(); return utf8 ? RCUTF8() : (char)s.ReadByte();}

        public char RCUTF8()
        {
            cR();
            byte t;
            int T;
            int val = 0;
            for (j = 0, i = 4; j < i; j++)
            {
                T = s.ReadByte();
                if (T == -1) return '\uFFFF';
                t = (byte)T;

                     if ((t & 0xC0) == 0x80 && j >  0)   val = (val << 6) | (t & 0x3F);
                else if ((t & 0x80) == 0x00 && j == 0)   return (char)t;
                else if ((t & 0xE0) == 0xC0 && j == 0) { val = t & 0x1F; i = 2; }
                else if ((t & 0xF0) == 0xE0 && j == 0) { val = t & 0x0F; i = 3; }
                else if ((t & 0xF8) == 0xF0 && j == 0) { val = t & 0x07; i = 4; }
                else return '\uFFFF';
            }
            return (char)val;
        }

        public string RS(long Length, bool utf8 = true)
        { cR(); return utf8 ? RSUTF8(Length) : RSASCII(Length);}

        public string RSUTF8 (long length) { cR(); return RBy(length).ToUTF8 (); }
        public string RSASCII(long length) { cR(); return RBy(length).ToASCII(); }

        public string RS(long? length, bool utf8 = true)
        { cR(); return utf8? RSUTF8(length) : RSASCII(length); }

        public string RSUTF8 (long? length) { cR(); return RBy(length).ToUTF8 (); }
        public string RSASCII(long? length) { cR(); return RBy(length).ToASCII(); }

        public byte[] RBy(long length, long offset = -1)
        { cR(); byte[] buf = new byte[length]; if (offset > -1) s.Position = offset;
            s.Read(buf, 0, (int)length); return buf; }

        public int RBy(long length, byte[] buf, long offset = -1)
        { cR(); if (offset > -1) s.Position = offset; return s.Read(buf, 0, (int)length); }

        public byte[] RBy(long? length, long offset = -1)
        { if (length == null) return new byte[0]; else return RBy((long)length, offset); }

        public void RBy(long length, byte bits, byte[] buf, long offset = -1)
        { if (offset > -1) s.Seek(offset, 0);
                 if (bits > 0 && bits < 8) for (i = 0; i < length; i++) buf[i] = RBi(bits); CR(); }

        public byte RBi(byte bits)
        {
            cR();
            bitRead += bits;
            tempBitRead = 8 - bitRead;
            if (tempBitRead < 0)
            {
                bitRead = (byte)-tempBitRead;
                tempBitRead = 8 + tempBitRead;
                valRead = (ushort)((valRead << 8) | (byte)s.ReadByte());
            }
            return (byte)((valRead >> tempBitRead) & ((1 << bits) - 1));
        }

        public byte RHB() => RBi(4);

        public void W(int val, byte bits)
        {
            cW();
            val &= (1 << bits) - 1;
            bitWrite += bits;
            tempBitWrite = 8 - bitWrite;
            if (tempBitWrite < 0)
            {
                bitWrite = (byte)-tempBitWrite;
                tempBitWrite = 8 + tempBitWrite;
                s.WriteByte((byte)(valWrite | (val >> bitWrite)));
                valWrite = 0;
            }
            valWrite |= val << tempBitWrite;
            valWrite &= 0xFF;
        }

        public void CR() //CheckRead
        { if (bitRead  > 0)                                      valRead  = 0; bitRead  = 8;   }
        public void CW() //CheckWrite
        { if (bitWrite > 0) { cW(); s.WriteByte((byte)valWrite); valWrite = 0; bitWrite = 0; } }

        public byte[] ToArray(bool close)
        { byte[] data = ToArray(); if (close) Dispose(); return data; }

        public byte[] ToArray()
        {
            long position = s.Position; s.Position = 0;
            byte[] data = new byte[s.Length];
            s.Read(data, 0, data.Length);
            s.Position = position;
            return data;
        }
    }

    public enum SeekOrigin
    {
        Begin   = 0,
        Current = 1,
        End     = 2,
    }
}
