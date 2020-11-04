using System;

namespace KKdEmbLib
{
    public struct KKC : IDisposable
    {
        private KKCKey key;
        public KKCKey Key => key;

        private KKCKeyMode mode;
        public KKCKeyMode Mode => mode;

        private KKCError error;
        public KKCError Error => error;

        private uint[] k;

        private uint a , b , e , f , p;
        private uint a0, b0, c0, c1, c2, c3, e0, f0, o0, o1, o2, o3;

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

        public KKC(byte[] key, KKCKeyMode mode = KKCKeyMode.Past)
        {
            a  = b  = e  = f  = p  = 0;
            a0 = b0 = c0 = c1 = c2 = c3 = e0 = f0 = o0 = o1 = o2 = o3 = 0;
            _state = 1;
            k = null;
            this.mode = 0;
            this.key = default;
            if (key == null) { error = KKCError.InvalidKey; return; }
            error = KKCError.InvalidKeyLength;

            KKCKeyType type = 0;
            int kl = key.Length;

            switch (kl)
            {
                case  16: type = KKCKeyType.KKC128 ; break;
                case  24: type = KKCKeyType.KKC192 ; break;
                case  32: type = KKCKeyType.KKC256 ; break;
                case  48: type = KKCKeyType.KKC384 ; break;
                case  64: type = KKCKeyType.KKC512 ; break;
                case  96: type = KKCKeyType.KKC768 ; break;
                case 128: type = KKCKeyType.KKC1024; break;
                case 196: type = KKCKeyType.KKC1536; break;
                case 256: type = KKCKeyType.KKC2048; break;
                default: return;
            }

            error = KKCError.None;
            this.key = new KKCKey(key, mode, type);
            this.mode = this.key.Mode;
        }

        public KKC(KKCKeyType type = KKCKeyType.KKC256, KKCKeyMode mode = KKCKeyMode.Past)
        {
            a  = b  = e  = f  = p  = 0;
            a0 = b0 = c0 = c1 = c2 = c3 = e0 = f0 = o0 = o1 = o2 = o3 = 0;
            _state = 1;
            k = null;
            this.mode = 0;
            key = default;
            error = KKCError.InvalidKeyLength;

            switch (type)
            {
                case KKCKeyType.KKC128:
                case KKCKeyType.KKC192:
                case KKCKeyType.KKC256:
                case KKCKeyType.KKC384:
                case KKCKeyType.KKC512:
                case KKCKeyType.KKC768:
                case KKCKeyType.KKC1024:
                case KKCKeyType.KKC1536:
                case KKCKeyType.KKC2048: break;
                default: return;
            }

            error = KKCError.None;
            key = KKCKey.GetNewKey(mode, type);
            this.mode = key.Mode;
        }

        public KKC(uint seed, KKCKeyType type = KKCKeyType.KKC256, KKCKeyMode mode = KKCKeyMode.Past)
        {
            a  = b  = e  = f  = p  = 0;
            a0 = b0 = c0 = c1 = c2 = c3 = e0 = f0 = o0 = o1 = o2 = o3 = 0;
            _state = seed;
            k = null;
            this.mode = 0;
            key = default;
            error = KKCError.InvalidKeyLength;

            switch (type)
            {
                case KKCKeyType.KKC128:
                case KKCKeyType.KKC192:
                case KKCKeyType.KKC256:
                case KKCKeyType.KKC384:
                case KKCKeyType.KKC512:
                case KKCKeyType.KKC768:
                case KKCKeyType.KKC1024:
                case KKCKeyType.KKC1536:
                case KKCKeyType.KKC2048: break;
                default: return;
            }

            error = KKCError.None;
            key = KKCKey.GetNewKey(mode, type);
            this.mode = key.Mode;
        }

        public KKC(KKCKey key)
        {
            a  = b  = e  = f  = p  = 0;
            a0 = b0 = c0 = c1 = c2 = c3 = e0 = f0 = o0 = o1 = o2 = o3 = 0;
            _state = 1;
            k = null;
            error = KKCError.None;
            mode = 0;
            this.key = default;

            if (key.NotNull) { this.key = key; mode = this.key.Mode; }
            else error = KKCError.InvalidKey;
        }

        public void PrepareCursingTable()
        {
            bool @return = true;
            if (key.IsNull) error = KKCError.InvalidKey;
            else @return = false;

            if (@return) return;

            uint kl = key.Length;
            byte[] arr = new byte[kl + 3];
            Array.Copy(key.Data, 0, arr, 0, kl);

            uint i;
            k = new uint[kl];
            while (true)
            {
                for (i = 0, b = kl / 2, a = 0, b0 = 0; i < b; i++)
                { a ^= k[i] = GetU32(arr, i * 2); b0 |= k[i]; }
                k[kl / 2 - 1] |= b = GetU32(arr, 0) << 16; a ^= b; b0 |= b;

                if (b0 != 0)
                {
                    for (i = 0, b = kl / 2; i < b; i++)
                    { a ^= k[b + i] = GetU32(arr, i * 2 + 1); b0 |= k[i]; }
                    k[kl - 2] |= b = GetU32(arr, 0) << 24; a ^= b; b0 |= b;
                    k[kl - 1] |= b = GetU32(arr, 0) <<  8; a ^= b; b0 |= b;

                    if (a != 0) break;
                }

                seed =         a ^ b0; NextBytes(arr);
                seed = GetU32(arr, 0); NextBytes(arr);
            }
            arr = null;

            a0 = a;
            e0 = XorU32(k[XorU32(~a0 + ((a0 >>  1) | (a0 << 31))) % kl]) % kl;
            f0 = XorU32(k[XorU32(~a0 - ((a0 >>  5) | (a0 << 27))) % kl]) % kl;
            Reset();
        }

        public void Reset()
        {
            uint kl = key.Length;
            o0 = o1 = o2 = o3 = a0;
            e = e0; f = f0;
        }

        public void Reset(uint iv)
        {
            uint kl = key.Length;
            o0 = o1 = o2 = o3 = a0 ^ iv;
            e = e0; f = f0;
        }

        public void Reset(uint iv0, uint iv1, uint iv2, uint iv3)
        {
            uint kl = key.Length;
            o0 = a0 ^ iv0; o1 = a0 ^ iv1; o2 = a0 ^ iv2; o3 = a0 ^ iv3;
            e = (e0 ^ XorU32(iv0 ^ iv2)) % kl;
            f = (f0 ^ XorU32(iv1 ^ iv3)) % kl;
        }

        public byte[] Curse(byte[] arr)
        {
            bool @return = true;
                 if (k              == null) error = KKCError.UninitializedTable;
            else if (arr            == null) error = KKCError.InvalidData;
            else if (arr.Length         < 1) error = KKCError.InvalidDataLength;
            else if (arr.Length % 0x10 != 0) error = KKCError.InvalidDataLength;
            else if (key.            IsNull) error = KKCError.InvalidKey;
            else @return = false;

            if (@return) return default;

            Reset();

            byte[] data = new byte[arr.LongLength];
            Curse(arr, data);
            return data;
        }

        public byte[] Decrypt(byte[] arr)
        {
            bool @return = true;
                 if (k              == null) error = KKCError.UninitializedTable;
            else if (arr            == null) error = KKCError.InvalidData;
            else if (arr.Length         < 1) error = KKCError.InvalidDataLength;
            else if (arr.Length % 0x10 != 0) error = KKCError.InvalidDataLength;
            else if (key.            IsNull) error = KKCError.InvalidKey;
            else @return = false;

            if (@return) return default;

            Reset();

            byte[] data = new byte[arr.LongLength];
            Decurse(arr, data);
            return data;
        }

        public void Curse(byte[] src, byte[] dst) =>
            Curse(src, dst, 0, 0, -1);

        public void Curse(byte[] src, byte[] dst, long srcOffset, long dstOffset) =>
            Curse(src, dst, srcOffset, dstOffset, -1);

        public unsafe void Curse(byte[] src, byte[] dst, long srcOffset, long dstOffset, long length)
        {
            bool @return = true;
                 if (k   == null) error = KKCError.UninitializedTable;
            else if (key .IsNull) error = KKCError.InvalidKey;
            else if (src == null) error = KKCError.InvalidData;
            else if (dst == null) error = KKCError.InvalidData;
            else @return = false;
            if (@return) return;

            @return = true;
            long l = length;
            long srco = srcOffset; srco = srco < 0 ? 0 : srco;
            long dsto = dstOffset; dsto = dsto < 0 ? 0 : dsto;
            long srcl = src.LongLength;
            long dstl = dst.LongLength;
                 if (srcl        <    1) error = KKCError.InvalidDataLength;
            else if (srcl - srco <    1) error = KKCError.InvalidDataLength;
            else if (srcl % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (srco % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dstl        <    1) error = KKCError.InvalidDataLength;
            else if (dstl - dsto <    1) error = KKCError.InvalidDataLength;
            else if (dstl % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dsto % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dstl        < srcl) error = KKCError.InvalidDataLength;
            else if (l == -1) @return = false;
            else if (l % 0x10    !=   0) error = KKCError.InvalidDataLength;
            else if (srcl - srco <    l) error = KKCError.InvalidDataLength;
            else if (dstl - dsto <    l) error = KKCError.InvalidDataLength;
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
                if (mode == KKCKeyMode.Simple)
                    for (i = 0; i < n; i++)
                    {
                        e = e0; f = f0;
                        p = f; f = e; e ^= f ^= p = XorU32(c0 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c1 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c2 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c3 = m[p]) % kl;

                        b = *s++; *d++ = b ^ c0;
                        b = *s++; *d++ = b ^ c1;
                        b = *s++; *d++ = b ^ c2;
                        b = *s++; *d++ = b ^ c3;
                    }
                else if (mode == KKCKeyMode.Past)
                    for (i = 0; i < n; i++)
                    {
                        p = f; f = e; e ^= f ^= p = XorU32(c0 = o2 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c1 = o0 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c2 = o3 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c3 = o1 ^ m[p]) % kl;

                        b = *s++; *d++ = o0 = b ^ c0 ^ o0;
                        b = *s++; *d++ = o1 = b ^ c1 ^ o1;
                        b = *s++; *d++ = o2 = b ^ c2 ^ o2;
                        b = *s++; *d++ = o3 = b ^ c3 ^ o3;
                    }
            }

            error = KKCError.None;
        }

        public void Decurse(byte[] src, byte[] dst) =>
            Decurse(src, dst, 0, 0, -1);

        public void Decurse(byte[] src, byte[] dst, long srcOffset, long dstOffset) =>
            Decurse(src, dst, srcOffset, dstOffset, -1);

        public unsafe void Decurse(byte[] src, byte[] dst, long srcOffset, long dstOffset, long length)
        {
            bool @return = true;
                 if (k   == null) error = KKCError.UninitializedTable;
            else if (key .IsNull) error = KKCError.InvalidKey;
            else if (src == null) error = KKCError.InvalidData;
            else if (dst == null) error = KKCError.InvalidData;
            else @return = false;
            if (@return) return;

            @return = true;
            long l = length;
            long srco = srcOffset; srco = srco < 0 ? 0 : srco;
            long dsto = dstOffset; dsto = dsto < 0 ? 0 : dsto;
            long srcl = src.LongLength;
            long dstl = dst.LongLength;
                 if (srcl        <    1) error = KKCError.InvalidDataLength;
            else if (srcl - srco <    1) error = KKCError.InvalidDataLength;
            else if (srcl % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (srco % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dstl        <    1) error = KKCError.InvalidDataLength;
            else if (dstl - dsto <    1) error = KKCError.InvalidDataLength;
            else if (dstl % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dsto % 0x10 !=   0) error = KKCError.InvalidDataLength;
            else if (dstl        < srcl) error = KKCError.InvalidDataLength;
            else if (l == -1) @return = false;
            else if (l % 0x10    !=   0) error = KKCError.InvalidDataLength;
            else if (srcl - srco <    l) error = KKCError.InvalidDataLength;
            else if (dstl - dsto <    l) error = KKCError.InvalidDataLength;
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
                if (mode == KKCKeyMode.Simple)
                    for (i = 0; i < n; i++)
                    {
                        e = e0; f = f0;
                        p = f; f = e; e ^= f ^= p = XorU32(c0 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c1 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c2 = m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c3 = m[p]) % kl;

                        b = *s++; *d++ = b ^ c0;
                        b = *s++; *d++ = b ^ c1;
                        b = *s++; *d++ = b ^ c2;
                        b = *s++; *d++ = b ^ c3;
                    }
                else if (mode == KKCKeyMode.Past)
                    for (i = 0; i < n; i++)
                    {
                        p = f; f = e; e ^= f ^= p = XorU32(c0 = o2 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c1 = o0 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c2 = o3 ^ m[p]) % kl;
                        p = f; f = e; e ^= f ^= p = XorU32(c3 = o1 ^ m[p]) % kl;

                        b = *s++; *d++ = b ^ c0 ^ o0; o0 = b; 
                        b = *s++; *d++ = b ^ c1 ^ o1; o1 = b;
                        b = *s++; *d++ = b ^ c2 ^ o2; o2 = b;
                        b = *s++; *d++ = b ^ c3 ^ o3; o3 = b;
                    }
            }

            error = KKCError.None;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime
            .CompilerServices.MethodImplOptions.AggressiveInlining)]
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

    public struct KKCKey
    {
        private byte[] data;
        private KKCKeyMode mode;
        private KKCKeyType type;

        public byte[] Data => data;
        public KKCKeyMode Mode => mode;
        public KKCKeyType Type => type;
        public uint Length => (byte)type * 8u;

        public bool  IsNull => data == null || data.Length != Length || mode <  KKCKeyMode.Simple
            || mode >  KKCKeyMode.Past || type <  KKCKeyType.KKC128 || type >  KKCKeyType.KKC2048;
        public bool NotNull => data != null && data.Length == Length && mode >= KKCKeyMode.Simple
            && mode <= KKCKeyMode.Past && type >= KKCKeyType.KKC128 && type <= KKCKeyType.KKC2048;

        public KKCKey(byte[] key, KKCKeyMode mode, KKCKeyType type)
        {
            data = null; this.mode = default; this.type = default;
            if (key == null || key.Length != (byte)type * 0x8) return;
            data = key; this.mode = mode; this.type = type;
        }

        public static KKCKey GetNewKey(KKCKeyMode mode = KKCKeyMode.Past,
            KKCKeyType type = KKCKeyType.KKC128) =>
            GetNewKey((uint)Environment.TickCount, mode, type);

        public static KKCKey GetNewKey(uint seed, KKCKeyMode mode = KKCKeyMode.Past,
            KKCKeyType type = KKCKeyType.KKC128)
        {
            uint _state = 1;
            if (seed != 0) _state = seed;

            switch (type)
            {
                case KKCKeyType.KKC128:
                case KKCKeyType.KKC192:
                case KKCKeyType.KKC256:
                case KKCKeyType.KKC384:
                case KKCKeyType.KKC512:
                case KKCKeyType.KKC768:
                case KKCKeyType.KKC1024:
                case KKCKeyType.KKC1536:
                case KKCKeyType.KKC2048: break;
                default: return default;
            }

            int l = (byte)type * 0x8;
            byte[] key = new byte[l];
            for (int i = 0; i < l; i++)
                key[i] = (byte)NextRand();

            return new KKCKey(key, mode, type);

            uint NextRand()
            { uint x = _state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return _state = x; }
        }
    }

    public enum KKCKeyType : byte
    {
        KKC128  =  2,
        KKC192  =  3,
        KKC256  =  4,
        KKC384  =  6,
        KKC512  =  8,
        KKC768  = 12,
        KKC1024 = 16,
        KKC1536 = 24,
        KKC2048 = 32,
    }

    public enum KKCKeyMode : byte
    {
        Simple = 1,
        Past   = 2,
    }

    public enum KKCError : byte
    {
        None               = 0,
        InvalidData        = 1,
        InvalidDataLength  = 2,
        InvalidKey         = 3,
        InvalidKeyLength   = 4,
        UninitializedTable = 5,
    }
}
