using System;

namespace KKdEmbLib
{
    public struct KKE : IDisposable
    {
        private Key key;
        public Key Key => key;

        private KeyMode mode;
        public KeyMode Mode => mode;

        private Error error;
        public Error Error => error;

        private uint[] k;

        private uint a , b, q , e , f , g , h , c0, c1, c2, c3;
        private uint a0,    q0, e0, f0, g0, h0, d0, d1, d2, d3;

        private uint _state;
        private uint seed { get => _state; set => _state = value == 0 ? 1 : value; }
        private uint NextRand()
        { uint x = _state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return _state = x; }

        private void NextBytes(byte[] arr)
        {
            if (arr == null || arr.Length < 1) return;
            int l = arr.Length;
            for (int i = 0; i < l; i++)
                arr[i] = (byte)NextRand();
        }

        public KKE(byte[] key, KeyMode mode = KeyMode.OFB)
        {
            a  = b = q  = e  = f  = g  = h  = c0 = c1 = c2 = c3 = 0;
            a0 =     q0 = e0 = f0 = g0 = h0 = d0 = d1 = d2 = d3 = 0;
            _state = 1;
            k = null;
            this.mode = 0;
            this.key = default;
            if (key == null) { error = Error.InvalidKey; return; }
            error = Error.InvalidKeyLength;

            KeyType keyType = 0;
            int kl = key.Length;

            switch (kl)
            {
                case  16: keyType = KeyType.KKE128 ; break;
                case  24: keyType = KeyType.KKE192 ; break;
                case  32: keyType = KeyType.KKE256 ; break;
                case  48: keyType = KeyType.KKE384 ; break;
                case  64: keyType = KeyType.KKE512 ; break;
                case  96: keyType = KeyType.KKE768 ; break;
                case 128: keyType = KeyType.KKE1024; break;
                case 196: keyType = KeyType.KKE1536; break;
                case 256: keyType = KeyType.KKE2048; break;
                default: return;
            }

            error = Error.None;
            this.key = new Key(key, mode, keyType);
            this.mode = this.key.Mode;
        }

        public KKE(KeyType type = KeyType.KKE256, KeyMode mode = KeyMode.OFB)
        {
            a  = b = q  = e  = f  = g  = h  = c0 = c1 = c2 = c3 = 0;
            a0 =     q0 = e0 = f0 = g0 = h0 = d0 = d1 = d2 = d3 = 0;
            _state = 1;
            k = null;
            this.mode = 0;
            key = default;
            error = Error.InvalidKeyLength;

            switch (type)
            {
                case KeyType.KKE128:
                case KeyType.KKE192:
                case KeyType.KKE256:
                case KeyType.KKE384:
                case KeyType.KKE512:
                case KeyType.KKE768:
                case KeyType.KKE1024:
                case KeyType.KKE1536:
                case KeyType.KKE2048: break;
                default: return;
            }

            error = Error.None;
            key = Key.GetNewKey(mode, type);
            this.mode = key.Mode;
        }

        public KKE(uint seed, KeyType type = KeyType.KKE256, KeyMode mode = KeyMode.OFB)
        {
            a  = b = q  = e  = f  = g  = h  = c0 = c1 = c2 = c3 = 0;
            a0 =     q0 = e0 = f0 = g0 = h0 = d0 = d1 = d2 = d3 = 0;
            _state = seed;
            k = null;
            this.mode = 0;
            key = default;
            error = Error.InvalidKeyLength;

            switch (type)
            {
                case KeyType.KKE128:
                case KeyType.KKE192:
                case KeyType.KKE256:
                case KeyType.KKE384:
                case KeyType.KKE512:
                case KeyType.KKE768:
                case KeyType.KKE1024:
                case KeyType.KKE1536:
                case KeyType.KKE2048: break;
                default: return;
            }

            error = Error.None;
            key = Key.GetNewKey(mode, type);
            this.mode = key.Mode;
        }

        public KKE(Key key)
        {
            a  = b = q  = e  = f  = g  = h  = c0 = c1 = c2 = c3 = 0;
            a0 =     q0 = e0 = f0 = g0 = h0 = d0 = d1 = d2 = d3 = 0;
            _state = 1;
            k = null;
            error = Error.None;
            mode = 0;
            this.key = default;

            if (key.NotNull) { this.key = key; mode = this.key.Mode; }
            else error = Error.InvalidKey;
        }

        public void PrepareEncryptionTable()
        {
            bool @return = true;
            if (key.IsNull) error = Error.InvalidKey;
            else @return = false;

            if (@return) return;

            uint kl = key.Length;
            byte[] arr = new byte[kl + 3];
            Array.Copy(key.Data, 0, arr, 0, kl);

            uint i;
            k = new uint[kl];
            while (true)
            {
                for (i = 0, b = kl / 2, a = 0, q = 0; i < b; i++)
                { a ^= k[i] = GetU32(arr, i * 2); q |= k[i]; }
                k[kl / 2 - 1] |= b = GetU32(arr, 0) << 16; a ^= b; q |= b;

                if (q != 0)
                {
                    for (i = 0, b = kl / 2; i < b; i++)
                    { a ^= k[b + i] = GetU32(arr, i * 2 + 1); q |= k[i]; }
                    k[kl - 2] |= b = GetU32(arr, 0) << 24; a ^= b; q |= b;
                    k[kl - 1] |= b = GetU32(arr, 0) <<  8; a ^= b; q |= b;

                    if (a != 0) break;
                }

                seed =          a ^ q; NextBytes(arr);
                seed = GetU32(arr, 0); NextBytes(arr);
            }
            arr = null;

            a0 = a;
            q0 = XorU32(~a0) % kl;
            e0 = XorU32(k[XorU32(    ~a0 + (a0 >> 1)) % kl]) % kl;
            f0 = XorU32(k[XorU32(    ~a0 - (a0 >> 5)) % kl]) % kl;
            g0 = XorU32(k[XorU32(e0 + f0 - (a0 >> 1)) % kl] )% kl;
            h0 = XorU32(k[XorU32(e0 - f0 + (a0 >> 5)) % kl]) % kl;

            Reset();
        }

        public void Reset()
        { d0 = d1 = d2 = d3 = a0; q = q0; e = e0; f = f0; g = g0; h = h0; }

        public void Reset(uint iv)
        { d0 = d1 = d2 = d3 = a0 ^ iv; q = q0; e = e0; f = f0; g = g0; h = h0; }

        public void Reset(uint iv0, uint iv1, uint iv2, uint iv3)
        {
            uint kl = key.Length;
            d0 = a0 ^ iv0; d1 = a0 ^ iv1; d2 = a0 ^ iv2; d3 = a0 ^ iv3;
            q = (q0 ^ XorU32(iv1)) % kl;
            e = (e0 ^ XorU32(iv2)) % kl;
            f = (f0 ^ XorU32(iv3)) % kl;
            g = (g0 ^ XorU32(iv0 ^ iv3)) % kl;
            h = (h0 ^ XorU32(iv1 ^ iv2)) % kl;
        }

        public byte[] Encrypt(byte[] arr)
        {
            bool @return = true;
                 if (k              == null) error = Error.UninitializedTable;
            else if (arr            == null) error = Error.InvalidData;
            else if (arr.Length         < 1) error = Error.InvalidDataLength;
            else if (arr.Length % 0x10 != 0) error = Error.InvalidDataLength;
            else if (key.            IsNull) error = Error.InvalidKey;
            else @return = false;

            if (@return) return default;

            Reset();

            byte[] data = new byte[arr.LongLength];
            Encrypt(arr, data);
            return data;
        }

        public byte[] Decrypt(byte[] arr)
        {
            bool @return = true;
                 if (k              == null) error = Error.UninitializedTable;
            else if (arr            == null) error = Error.InvalidData;
            else if (arr.Length         < 1) error = Error.InvalidDataLength;
            else if (arr.Length % 0x10 != 0) error = Error.InvalidDataLength;
            else if (key.            IsNull) error = Error.InvalidKey;
            else @return = false;

            if (@return) return default;

            Reset();

            byte[] data = new byte[arr.LongLength];
            Decrypt(arr, data);
            return data;
        }

        public unsafe void Encrypt(byte[] src, byte[] dst) =>
            Encrypt(src, dst, 0, 0, -1);

        public unsafe void Encrypt(byte[] src, byte[] dst, long srcOffset, long dstOffset) =>
            Encrypt(src, dst, srcOffset, dstOffset, -1);

        public unsafe void Encrypt(byte[] src, byte[] dst, long srcOffset, long dstOffset, long length)
        {
            bool @return = true;
                 if (k   == null) error = Error.UninitializedTable;
            else if (key .IsNull) error = Error.InvalidKey;
            else if (src == null) error = Error.InvalidData;
            else if (dst == null) error = Error.InvalidData;
            else @return = false;
            if (@return) return;

            @return = true;
            long l = length;
            long srco = srcOffset; srco = srco < 0 ? 0 : srco;
            long dsto = dstOffset; dsto = dsto < 0 ? 0 : dsto;
            long srcl = src.LongLength;
            long dstl = dst.LongLength;
                 if (srcl        <    1) error = Error.InvalidDataLength;
            else if (srcl - srco <    1) error = Error.InvalidDataLength;
            else if (srcl % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (srco % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dstl        <    1) error = Error.InvalidDataLength;
            else if (dstl - dsto <    1) error = Error.InvalidDataLength;
            else if (dstl % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dsto % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dstl        < srcl) error = Error.InvalidDataLength;
            else if (l == -1) @return = false;
            else if (l % 0x10    !=   0) error = Error.InvalidDataLength;
            else if (srcl - srco <    l) error = Error.InvalidDataLength;
            else if (dstl - dsto <    l) error = Error.InvalidDataLength;
            else @return = false;
            if (@return) return;

            uint kl = key.Length;
            long len = l > 0 ? l : (srcl - srco) / 4;

            fixed (uint* m = k)
            fixed (byte* srcPtr = src)
            fixed (byte* dstPtr = dst)
            {
                uint* s = (uint*)(srcPtr + srco);
                uint* d = (uint*)(dstPtr + dsto);
                long n = len / 4;
                uint i;
                if (mode == KeyMode.ECB)
                    for (i = 0; i < n; i++)
                    {
                        q = q0; e = e0; f = f0; g = g0; h = h0;
                        c0 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c0) % kl;
                        c1 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c1) % kl;
                        c2 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c2) % kl;
                        c3 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c3) % kl;

                        *d++ = *s++ ^ c0;
                        *d++ = *s++ ^ c1;
                        *d++ = *s++ ^ c2;
                        *d++ = *s++ ^ c3;
                    }
                else if (mode == KeyMode.OFB)
                    for (i = 0; i < n; i++)
                    {
                        c0 = d0 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c0) % kl;
                        c1 = d1 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c1) % kl;
                        c2 = d2 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c2) % kl;
                        c3 = d3 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c3) % kl;

                        *d++ = d0 = *s++ ^ c0;
                        *d++ = d1 = *s++ ^ c1;
                        *d++ = d2 = *s++ ^ c2;
                        *d++ = d3 = *s++ ^ c3;
                    }
            }

            error = Error.None;
        }

        public unsafe void Decrypt(byte[] src, byte[] dst) =>
            Decrypt(src, dst, 0, 0, -1);

        public unsafe void Decrypt(byte[] src, byte[] dst, long srcOffset, long dstOffset) =>
            Decrypt(src, dst, srcOffset, dstOffset, -1);

        public unsafe void Decrypt(byte[] src, byte[] dst, long srcOffset, long dstOffset, long length)
        {
            bool @return = true;
                 if (k   == null) error = Error.UninitializedTable;
            else if (key .IsNull) error = Error.InvalidKey;
            else if (src == null) error = Error.InvalidData;
            else if (dst == null) error = Error.InvalidData;
            else @return = false;
            if (@return) return;

            @return = true;
            long l = length;
            long srco = srcOffset; srco = srco < 0 ? 0 : srco;
            long dsto = dstOffset; dsto = dsto < 0 ? 0 : dsto;
            long srcl = src.LongLength;
            long dstl = dst.LongLength;
                 if (srcl        <    1) error = Error.InvalidDataLength;
            else if (srcl - srco <    1) error = Error.InvalidDataLength;
            else if (srcl % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (srco % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dstl        <    1) error = Error.InvalidDataLength;
            else if (dstl - dsto <    1) error = Error.InvalidDataLength;
            else if (dstl % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dsto % 0x10 !=   0) error = Error.InvalidDataLength;
            else if (dstl        < srcl) error = Error.InvalidDataLength;
            else if (l == -1) @return = false;
            else if (l % 0x10    !=   0) error = Error.InvalidDataLength;
            else if (srcl - srco <    l) error = Error.InvalidDataLength;
            else if (dstl - dsto <    l) error = Error.InvalidDataLength;
            else @return = false;
            if (@return) return;

            uint kl = key.Length;
            long len = l > 0 ? l : (srcl - srco) / 4;

            fixed (uint* m = k)
            fixed (byte* srcPtr = src)
            fixed (byte* dstPtr = dst)
            {
                uint* s = (uint*)(srcPtr + srco);
                uint* d = (uint*)(dstPtr + dsto);
                long n = len / 4;
                uint i;
                if (mode == KeyMode.ECB)
                    for (i = 0; i < n; i++)
                    {
                        q = q0; e = e0; f = f0; g = g0; h = h0;
                        c0 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c0) % kl;
                        c1 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c1) % kl;
                        c2 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c2) % kl;
                        c3 = m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c3) % kl;

                        *d++ = *s++ ^ c0;
                        *d++ = *s++ ^ c1;
                        *d++ = *s++ ^ c2;
                        *d++ = *s++ ^ c3;
                    }
                else if (mode == KeyMode.OFB)
                    for (i = 0; i < n; i++)
                    {
                        c0 = d0 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c0) % kl;
                        c1 = d1 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c1) % kl;
                        c2 = d2 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c2) % kl;
                        c3 = d3 ^ m[q] ^ m[e] ^ m[f] ^ m[g] ^ m[h];
                        h = g; g = f; f = e; e = q; e ^= f ^= g ^= h ^= q = XorU32(c3) % kl;

                        b = *s++; *d++ = b ^ c0; d0 = b;
                        b = *s++; *d++ = b ^ c1; d1 = b;
                        b = *s++; *d++ = b ^ c2; d2 = b;
                        b = *s++; *d++ = b ^ c3; d3 = b;
                    }
            }

            error = Error.None;
        }

        private static byte XorU32(uint val) =>
                (byte)(val ^ (val >> 8) ^ (val >> 16) ^ (val >> 24));

        private static uint GetU32(byte[] arr, uint offset = 0) =>
                     arr[offset    ]        | ((uint)arr[offset + 1] <<  8)
            | ((uint)arr[offset + 2] << 16) | ((uint)arr[offset + 3] << 24);

        private static void SetU32(uint val, byte[] arr, uint offset = 0)
        { arr[offset + 0] = (byte) val;        arr[offset + 1] = (byte)(val >>  8);
          arr[offset + 2] = (byte)(val >> 16); arr[offset + 3] = (byte)(val >> 24); }

        public void Dispose() { error = 0; _state = 1; }
    }

    public struct Key
    {
        private byte[] data;
        private KeyMode mode;
        private KeyType type;

        public byte[] Data => data;
        public KeyMode Mode => mode;
        public KeyType Type => type;
        public uint Length => (byte)type * 8u;

        public bool  IsNull => data == null || data.Length != Length || mode <  KeyMode.ECB
            || mode >  KeyMode.OFB || type <  KeyType.KKE128 || type >  KeyType.KKE2048;
        public bool NotNull => data != null && data.Length == Length && mode >= KeyMode.ECB
            && mode <= KeyMode.OFB && type >= KeyType.KKE128 && type <= KeyType.KKE2048;

        public Key(byte[] key, KeyMode mode, KeyType type)
        {
            data = null; this.mode = default; this.type = default;
            if (key == null || key.Length != (byte)type * 0x8) return;
            data = key; this.mode = mode; this.type = type;
        }

        public static Key GetNewKey(KeyMode mode = KeyMode.OFB,
            KeyType type = KeyType.KKE128) =>
            GetNewKey((uint)Environment.TickCount, mode, type);

        public static Key GetNewKey(uint seed, KeyMode mode = KeyMode.OFB,
            KeyType type = KeyType.KKE128)
        {
            uint _state = 1;
            if (seed != 0) _state = seed;

            switch (type)
            {
                case KeyType.KKE128:
                case KeyType.KKE192:
                case KeyType.KKE256:
                case KeyType.KKE384:
                case KeyType.KKE512:
                case KeyType.KKE768:
                case KeyType.KKE1024:
                case KeyType.KKE1536:
                case KeyType.KKE2048: break;
                default: return default;
            }

            int l = (byte)type * 0x8;
            byte[] key = new byte[l];
            for (int i = 0; i < l; i++)
                key[i] = (byte)NextRand();

            return new Key(key, mode, type);

            uint NextRand()
            { uint x = _state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return _state = x; }
        }
    }

    public enum KeyType : byte
    {
        KKE128  =  2,
        KKE192  =  3,
        KKE256  =  4,
        KKE384  =  6,
        KKE512  =  8,
        KKE768  = 12,
        KKE1024 = 16,
        KKE1536 = 24,
        KKE2048 = 32,
    }

    public enum KeyMode : byte
    {
        ECB = 1,
        OFB = 2,
    }

    public enum Error : byte
    {
        None               = 0,
        InvalidData        = 1,
        InvalidDataLength  = 2,
        InvalidKey         = 3,
        InvalidKeyLength   = 4,
        UninitializedTable = 5,
    }
}
