using System;
using KKdEmbLib.IO;

namespace KKdEmbLib
{
    public struct FilePacker : IDisposable
    {
        private const int hA = 0x1000; // Header Alignment
        private const int dA = 0x4000; // Data   Alignment

        private uint _state;
        private uint NextRand()
        { uint x = _state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return _state = x; }

        private void NextBytes(byte[] arr)
        {
            if (arr == null || arr.Length < 1) return;
            int l = arr.Length;
            for (int i = 0; i < l; i++)
                arr[i] = (byte)NextRand();
        }

        private static byte[] header = { 0x4B, 0x4F, 0x52, 0x45, 0x4E, 0x20, 0x46, 0x49,
                                         0x4C, 0x45, 0x50, 0x41, 0x43, 0x4B, 0x45, 0x52 };
        private static byte[] headdf = { 0x4B, 0x4F, 0x52, 0x45, 0x4E, 0x20, 0x46, 0x49,
                                         0x4C, 0x45, 0x20, 0x44, 0x49, 0x46, 0x46, 0x20 };

        private const long headerLength = 0x40;
        private const long headdfLength = 0x50;
        private const long rootDataLength = 0x10;

        private byte[] key;
        private KKC curse;

        public byte[] Key => key;

        public FilePacker(byte[] key)
        {
            _state = 1;
            curse = default;
            this.key = null;

            NewKey(ref curse, key);
        }

        public FilePacker(string password)
        {
            _state = 1;
            curse = default;
            key = null;

            NewKey(ref curse, password);
        }

        private void NewKey(ref KKC curse, byte[] key)
        {
            if (key == null || key.Length != 64) return;

            this.key = key;
            curse = new KKC(key, KKCKeyMode.Past);
            curse.PrepareCursingTable();
        }

        private void NewKey(ref KKC curse, string password)
        {
            if (password != null)
                _state = (uint)(password.Length > 0 ? password.Length : 1);

            key = new byte[64];
            uint a = NextRand();
            if (password != null)
            {
                int passLen = password.Length;
                for (int i = 0; i < passLen; i++)
                {
                    uint b = (char)password[i];
                    b = (b << 24) | (b << 16) | (b << 8) | b;
                    a ^= (a << 16) ^ b;
                }
            }

            _state = a;
            for (int i = 0; i < 0x40; i++)
                a ^= (a << 16) ^ NextRand();
            _state = a;
            NextBytes(key);

            curse = new KKC(key, KKCKeyMode.Past);
            curse.PrepareCursingTable();
        }

        public void Pack(string path, string file)
        {
            if (key == null || path == null || file == null || curse.Error != 0) return;

            long i;
            string p = path;
            if (!p.EndsWith("\\")) p += "\\";

            FilePackerData fpd = default;
            ScanDir(p, out string[] pre_files, out string[] pre_dirs);

            fpd. DirsCount = pre_dirs .LongLength;
            fpd.FilesCount = pre_files.LongLength;

            fpd. DirsData = new DirData[fpd. DirsCount];
            fpd.FilesData = new       FileData[fpd.FilesCount];

            ref DirData r = ref fpd.RootDir;
            System.IO.FileInfo ri = new System.IO.FileInfo(p);
            r.Unused = 0;
            r.Attributes = ((uint)ri.Attributes) & 0xFFFFFFF;
            r.Attributes |= (uint)DataMode.Store << 28;
            r.LastWriteTime = ri.LastWriteTimeUtc.Ticks;

            for (i = 0; i < fpd.DirsCount; i++)
            {
                DirData d = default;

                d.Name = pre_dirs[i].Replace(p, "");
                d.Unused = 0;

                System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(pre_dirs[i]);
                d.Attributes = ((uint)di.Attributes) & 0xFFFFFFF;
                d.Attributes |= (uint)DataMode.Store << 28;
                d.LastWriteTime = di.LastWriteTimeUtc.Ticks;

                fpd.DirsData[i] = d;
            }

            _state = (uint)(fpd.FilesCount + fpd.DirsCount);
            if (_state == 0) _state = (uint)Environment.TickCount;

            for (i = 0; i < fpd.FilesCount; i++)
            {
                FileData f = default;

                f.Name = pre_files[i].Replace(p, "");
                f.IV = NextRand();

                System.IO.FileInfo fi = new System.IO.FileInfo(pre_files[i]);
                f.Attributes = ((uint)fi.Attributes) & 0xFFFFFFF;
                f.Attributes |= (uint)DataMode.Store << 28;
                f.  CreationTime = fi.  CreationTimeUtc.Ticks;
                f. LastWriteTime = fi. LastWriteTimeUtc.Ticks;
                f.LastAccessTime = fi.LastAccessTimeUtc.Ticks;
                f.DataLength = fi.Length;

                fpd.FilesData[i] = f;
            }

            _state ^= (uint)Environment.TickCount;
            fpd.IV0 = NextRand();
            fpd.IV1 = NextRand();
            fpd.IV2 = NextRand();
            fpd.IV3 = NextRand();

            byte[] h = WriteHeader(ref fpd);

            curse.Reset(fpd.IV0, fpd.IV1, fpd.IV2, fpd.IV3);
            curse.Curse(h, h, 0x10, 0x10);

            file = file.EndsWith(".kkfp") ? file : file + ".kkfp";
            Stream s = File.OpenWriter(file, true);
            s.W(h);
            s.F();

            Stream s1;
            long j, l;
            byte[] buf = new byte[dA];
            for (i = 0; i < fpd.FilesCount; i++)
                using (s1 = File.OpenReader(pre_files[i]))
                {
                    ref FileData fd = ref fpd.FilesData[i];
                    Console.WriteLine($"Packing \"{fd.Name}\"");
                    l = s1.L / dA;
                    
                    curse.Reset(fd.IV);
                    for (j = 0; j < l; j++)
                    {
                        s1.RBy(dA, buf);
                        curse.Curse(buf, buf);
                        s.W(buf, dA);
                    }

                    l = s1.L - l * dA;
                    if (l == 0) continue;

                    NextBytes(buf);
                    s1.RBy(l, buf);
                    curse.Curse(buf, buf);
                    s.W(buf, (int)l.A(hA));
                    s.F();
                }
            s.C();

            System.IO.FileInfo rfi = new System.IO.FileInfo(file)
            {
                  CreationTimeUtc = new DateTime(r.LastWriteTime),
                 LastWriteTimeUtc = new DateTime(r.LastWriteTime),
                LastAccessTimeUtc = new DateTime(r.LastWriteTime)
            };

            static void ScanDir(string path, out string[] f, out string[] d)
            {
                try { f = Directory.GetFiles(path); d = new string[0]; }
                catch (Exception) { f = new string[0]; d = new string[0]; return; }
                string[] dirs = Directory.GetDirectories(path);
                d = MergeWith(d, dirs);
                foreach (string dir in dirs)
                {
                    ScanDir(dir, out string[] ff, out string[] dd);
                    f = MergeWith(f, ff);
                    d = MergeWith(d, dd);
                }
            }
        }

        public void Unpack(string path, string path2, bool showHidden)
        {
            if (key == null || path == null || path2 == null || curse.Error != 0) return;

            FilePackerData fpd = ReadHeader(path, ref curse);
            if (fpd.DataOffset < 0x400 || fpd.DataOffset % 0x400 != 0) return;
            SaveFiles(path, path2, curse, fpd, showHidden);
        }

        public void Unpack(string path, string password, string[] paths, string[] passwords, bool showHidden)
        {
            if (key == null || path == null || curse.Error != 0 || paths == null
                || passwords == null || paths.Length < 1 || passwords.Length < 1
                || paths.Length != passwords.Length || password == null) return;

            int c = paths.Length;
            KKC[] curses = new KKC[c + 1];
            FilePackerData[] fpds = new FilePackerData[c + 1];

            Array.Resize(ref paths, c + 1);
            Array.Copy(paths, 0, paths, 1, c);
            paths[0] = path;
            path = paths[c];

            key = null;
            curses[0] = default;
            NewKey(ref curses[0], password);
            if (key == null || curses[0].Error != 0) return;

            fpds[0] = ReadHeader(paths[0], ref curses[0]);
            if (fpds[0].DataOffset < 0x400 || fpds[0].DataOffset % 0x400 != 0) return;

            for (int i = 0, j = 1; i < c; i++, j++)
            {
                key = null;
                curses[j] = default;
                NewKey(ref curses[j], passwords[i]);
                if (key == null || curses[j].Error != 0) return;

                fpds[j] = ReadHeader(paths[j], ref curses[j]);
                if (fpds[j].DataOffset < 0x400 || fpds[j].DataOffset % 0x400 != 0) return;
                else if (!(fpds[j].ParentHash0 == 0 && fpds[j].ParentHash1 == 0 && fpds[j].ParentHash2 == 0)
                    && (fpds[j].ParentHash0 != fpds[i].Hash0 || fpds[j].ParentHash1 != fpds[i].Hash1
                      || fpds[j].ParentHash2 != fpds[i].Hash2)) return;
            }

            for (int j = c; j >= 0; j--)
                SaveFiles(path, paths[j], curses[j], fpds[j], showHidden);
        }

        public void Unpack(string path, string path2, byte[] key, string[] paths, byte[][] keys, bool showHidden)
        {
            if (this.key == null || path == null || path2 == null || curse.Error != 0 || paths == null || keys == null
                || paths.Length < 1 || keys.Length < 1 || paths.Length != keys.Length || key == null) return;

            int c = paths.Length;
            KKC[] curses = new KKC[c + 1];
            FilePackerData[] fpds = new FilePackerData[c + 1];

            Array.Resize(ref paths, c + 1);
            Array.Copy(paths, 0, paths, 1, c);
            paths[0] = path;

            this.key = null;
            curses[0] = default;
            NewKey(ref curses[0], key);
            if (this.key == null || curses[0].Error != 0) return;

            fpds[0] = ReadHeader(paths[0], ref curses[0]);
            if (fpds[0].DataOffset < 0x400 || fpds[0].DataOffset % 0x400 != 0) return;

            for (int i = 0, j = 1; i < c; i++, j++)
            {
                this.key = null;
                curses[j] = default;
                NewKey(ref curses[j], keys[i]);
                if (this.key == null || curses[j].Error != 0) return;

                fpds[j] = ReadHeader(paths[j], ref curses[j]);
                if (fpds[j].DataOffset < 0x400 || fpds[j].DataOffset % 0x400 != 0) return;
                else if (!(fpds[i].ParentHash0 == 0 && fpds[i].ParentHash1 == 0 && fpds[i].ParentHash2 == 0)
                    && (fpds[j].Hash0 != fpds[i].ParentHash0 || fpds[j].Hash1 != fpds[i].ParentHash1
                      || fpds[j].Hash2 != fpds[i].ParentHash2)) return;
            }

            for (int j = c; j >= 0; j--)
                SaveFiles(paths[j], path2, curses[j], fpds[j], showHidden);
        }

        private void SaveFiles(string path, string path2, KKC curse, FilePackerData fpd, bool showHidden)
        {
            DataMode dm;
            long i;

            if (fpd.NameOffset < 0x1000 || fpd.DataOffset < 0x1000) return;

            string[] pre_dirs  = new string[fpd. DirsCount];
            string[] pre_files = new string[fpd.FilesCount];

            dm = (DataMode)(fpd.RootDir.Attributes >> 28);
            string p;
            if (Path.GetFileNameWithoutExtension(path2) != Path.GetFileName(path2))
                p = Directory.GetCurrentDirectory() + "\\" + Path.GetFileNameWithoutExtension(path2);
            else
                p = path2;
            if (dm == DataMode.Store)
                Directory.CreateDirectory(p);

            System.IO.FileAttributes rootAttrib = new System.IO.DirectoryInfo(p).Attributes;
            new System.IO.DirectoryInfo(p) { Attributes = rootAttrib | System.IO.FileAttributes.Hidden, };

            for (i = 0; i < fpd.DirsCount; i++)
            {
                pre_dirs[i] = p + "\\" + fpd.DirsData[i].Name;
                dm = (DataMode)(fpd.DirsData[i].Attributes >> 28);
                if (dm != DataMode.Delete)
                    Directory.CreateDirectory(pre_dirs[i]);
            }

            Stream s = File.OpenReader(path);
            Stream s1;
            byte[] buf = new byte[dA];
            long j, l;
            s.OI64 = fpd.DataOffset;
            for (i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];
                pre_files[i] = p + "\\" + fd.Name;
                dm = (DataMode)(fd.Attributes >> 28);

                if (dm == DataMode.Store || dm == DataMode.Replace)
                    using (s1 = File.OpenWriter(pre_files[i]))
                    {
                        Console.WriteLine($"Unpacking \"{fd.Name}\"");
                        s.PI64 = fd.DataOffset;
                        l = fd.DataLength / dA;

                        curse.Reset(fd.IV);
                        for (j = 0; j < l; j++)
                        {
                            s.RBy(dA, buf);
                            curse.Decurse(buf, buf);
                            s1.W(buf, dA);
                        }

                        l = fd.DataLength - l * dA;
                        if (l == 0) continue;

                        s.RBy(l.A(hA), buf);
                        curse.Decurse(buf, buf);
                        s1.W(buf, (int)l);
                    }

                if (File.Exists(pre_files[i]))
                    if (dm == DataMode.Store || dm == DataMode.Change || dm == DataMode.Replace)
                        new System.IO.FileInfo(pre_files[i])
                        {
                            Attributes = (System.IO.FileAttributes)(fd.Attributes & 0xFFFFFFF),
                              CreationTimeUtc = new DateTime(fd.  CreationTime),
                             LastWriteTimeUtc = new DateTime(fd. LastWriteTime),
                            LastAccessTimeUtc = new DateTime(fd.LastAccessTime),
                        };
                    else if (dm == DataMode.Delete)
                        File.Delete(pre_files[i]);
            }
            s.C();

            for (i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData d = ref fpd.DirsData[i];
                dm = (DataMode)(d.Attributes >> 28);
                if (Directory.Exists(pre_dirs[i]) && dm == DataMode.Delete)
                    Directory.Delete(pre_dirs[i], true);
            }


            for (i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData d = ref fpd.DirsData[i];
                dm = (DataMode)(d.Attributes >> 28);
                if (Directory.Exists(pre_dirs[i]))
                    if (dm == DataMode.Delete)
                        Directory.Delete(pre_dirs[i], true);
                    else
                        new System.IO.DirectoryInfo(pre_dirs[i])
                        {
                            Attributes = (System.IO.FileAttributes)(d.Attributes & 0xFFFFFFF),
                              CreationTimeUtc = new DateTime(d.LastWriteTime),
                             LastWriteTimeUtc = new DateTime(d.LastWriteTime),
                            LastAccessTimeUtc = new DateTime(d.LastWriteTime),
                        };
            }

            new System.IO.DirectoryInfo(p) { Attributes = rootAttrib, };
            DirData r = fpd.RootDir;
            new System.IO.DirectoryInfo(p)
            {
                Attributes = (System.IO.FileAttributes)(r.Attributes & (showHidden ? 0xFFFFFFD : 0xFFFFFFF)),
                  CreationTimeUtc = new DateTime(r.LastWriteTime),
                 LastWriteTimeUtc = new DateTime(r.LastWriteTime),
                LastAccessTimeUtc = new DateTime(r.LastWriteTime),
            };
        }

        public void Differentiate(string path, string password, string[] paths, string[] passwords)
        {
            if (key == null || path == null || curse.Error != 0 || paths == null
                || passwords == null || paths.Length < 1 || passwords.Length < 1
                || paths.Length != passwords.Length || password == null) return;

            int c = paths.Length;
            KKC[] curses = new KKC[c + 1];
            FilePackerData[] fpds = new FilePackerData[c + 1];

            Array.Resize(ref paths, c + 1);
            Array.Copy(paths, 0, paths, 1, c);
            paths[0] = path;

            key = null;
            curses[0] = default;
            NewKey(ref curses[0], password);
            if (key == null || curses[0].Error != 0) return;

            fpds[0] = ReadHeader(path, ref curses[0]);
            if (fpds[0].DataOffset < 0x400 || fpds[0].DataOffset % 0x400 != 0) return;

            for (int i = 0, j = 1; i < c; i++, j++)
            {
                key = null;
                curses[j] = default;
                NewKey(ref curses[j], passwords[i]);
                if (key == null || curses[j].Error != 0) return;

                fpds[j] = ReadHeader(paths[j], ref curses[j]);
                if (fpds[j].DataOffset < 0x400 || fpds[j].DataOffset % 0x400 != 0) return;
                else if (fpds[j].ParentHash0 == 0 && fpds[j].ParentHash1 == 0 && fpds[j].ParentHash2 == 0) continue;
                else if (fpds[j].ParentHash0 != fpds[i].Hash0 || fpds[j].ParentHash1 != fpds[i].Hash1
                      || fpds[j].ParentHash2 != fpds[i].Hash2) return;
            }
            Differentiate(paths, curses, fpds);
        }

        public void Differentiate(string path, byte[] key, string[] paths, byte[][] keys)
        {
            if (this.key == null || path == null || curse.Error != 0 || paths == null || keys == null
                || paths.Length < 1 || keys.Length < 1 || paths.Length != keys.Length || key == null) return;

            int c = paths.Length;
            KKC[] curses = new KKC[c + 1];
            FilePackerData[] fpds = new FilePackerData[c + 1];

            Array.Resize(ref paths, c + 1);
            Array.Copy(paths, 0, paths, 1, c);
            paths[0] = path;

            this.key = null;
            curses[0] = default;
            NewKey(ref curses[0], key);
            if (this.key == null || curses[0].Error != 0) return;

            fpds[0] = ReadHeader(path, ref curses[0]);
            if (fpds[0].DataOffset < 0x400 || fpds[0].DataOffset % 0x400 != 0) return;

            for (int i = 0, j = 1; i < c; i++, j++)
            {
                this.key = null;
                curses[j] = default;
                NewKey(ref curses[j], keys[i]);
                if (this.key == null || curses[j].Error != 0) return;

                fpds[j] = ReadHeader(paths[j], ref curses[j]);
                if (fpds[j].DataOffset < 0x400 || fpds[j].DataOffset % 0x400 != 0) return;
            }
            Differentiate(paths, curses, fpds);
        }

        private void Differentiate(string[] paths, KKC[] curses, FilePackerData[] fpds)
        {
            long i, j, l, k;

            int c = fpds.Length;
            if (c < 2) return;

            j = c - 1;
            ulong hash0 = fpds[j].Hash0;
             uint hash1 = fpds[j].Hash1;
             uint hash2 = fpds[j].Hash2;

            Diff diff = default;
            diff. DirStore   = KKdDict<string,  DirData>.New;
            diff. DirChange  = KKdDict<string,  DirData>.New;
            diff. DirNoEdit  = KKdDict<string,  DirData>.New;
            diff. DirDelete  = KKdDict<string,  DirData>.New;
            diff.FileStore   = KKdDict<string, FileData>.New;
            diff.FileChange  = KKdDict<string, FileData>.New;
            diff.FileNoEdit  = KKdDict<string, FileData>.New;
            diff.FileDelete  = KKdDict<string, FileData>.New;
            diff.FileReplace = KKdDict<string, FileData>.New;

            Stream[] ss = new Stream[c];
            for (i = 0; i < c; i++)
            {
                ss[i] = File.OpenReader(paths[i]);
                ss[i].OI64 = fpds[i].DataOffset;
            }

            Console.WriteLine($"Reading \"{Path.GetFileName(paths[j])}\"");
            Compare(ss[j], curses, fpds, (int)j, ref diff);
            for (j = c - 2; j >= 0; j--)
            {
                Console.WriteLine($"Reading \"{Path.GetFileName(paths[j])}\"");
                Compare(ss[j], curses, fpds, (int)j, ref diff);

                FilePackerData fpd = default;
                fpd.ParentHash0 = hash0;
                fpd.ParentHash1 = hash1;
                fpd.ParentHash2 = hash2;
                fpd. DirsData = MergeWith(diff.DirStore.ToArray(), diff.DirChange.ToArray());
                fpd. DirsData = MergeWith( fpd.DirsData          , diff.DirNoEdit.ToArray());
                fpd. DirsData = MergeWith( fpd.DirsData          , diff.DirDelete.ToArray());
                fpd.FilesData = MergeWith(diff.FileStore.ToArray(), diff.FileChange.ToArray());
                fpd.FilesData = MergeWith(fpd.FilesData, diff.FileNoEdit .ToArray());
                fpd.FilesData = MergeWith(fpd.FilesData, diff.FileDelete .ToArray());
                fpd.FilesData = MergeWith(fpd.FilesData, diff.FileReplace.ToArray());
                fpd. DirsCount = fpd. DirsData.LongLength;
                fpd.FilesCount = fpd.FilesData.LongLength;
                fpd.RootDir.Attributes    = fpds[j].RootDir.Attributes;
                fpd.RootDir.LastWriteTime = fpds[j].RootDir.LastWriteTime;
                fpd.RootDir.Unused        = fpds[j].RootDir.Unused;

                _state = (uint)(fpd.FilesCount + fpd.DirsCount);
                if (_state == 0) _state = (uint)Environment.TickCount;

                _state ^= (uint)Environment.TickCount;
                fpd.IV0 = NextRand();
                fpd.IV1 = NextRand();
                fpd.IV2 = NextRand();
                fpd.IV3 = NextRand();

                byte[] h = WriteHeader(ref fpd, true);
                hash0 = h.CalculateChecksum0(h.LongLength);
                hash1 = h.CalculateChecksum1(h.LongLength);
                hash2 = h.CalculateChecksum2(h.LongLength);

                curses[j].Reset(fpd.IV0, fpd.IV1, fpd.IV2, fpd.IV3);
                curses[j].Curse(h, h, 0x10, 0x10);

                Stream s = File.OpenWriter(getPath(paths[j]), true);
                s.W(h);
                s.F();

                DataMode dm;
                byte[] buf = new byte[dA];
                for (i = 0; i < fpd.FilesCount; i++)
                {
                    ref FileData fd = ref fpd.FilesData[i];
                    ref Stream s1 = ref ss[fd.Index];
                    dm = (DataMode)(fd.Attributes >> 28);
                    if (dm == DataMode.Change || dm == DataMode.NoEdit || dm == DataMode.Delete) continue;
                    
                    Console.WriteLine($"Packing \"{fd.Name}\"");
                    s1.PI64 = fd.OldDataOffset;
                    l = fd.DataLength / dA;

                    for (k = 0; k < l; k++)
                    { s1.RBy(dA, buf); s.W(buf, dA); }

                    l = fd.DataLength - l * dA;
                    if (l == 0) continue;
                        
                    l = l.A(hA);
                    s1.RBy(l, buf); s.W(buf, (int)l);
                    s.F();
                }
                s.C();

                DateTime dt = DateTime.UtcNow;
                System.IO.FileInfo rfi = new System.IO.FileInfo(getPath(paths[j]))
                {
                      CreationTimeUtc = new DateTime(fpd.RootDir.LastWriteTime),
                     LastWriteTimeUtc = new DateTime(fpd.RootDir.LastWriteTime),
                    LastAccessTimeUtc = new DateTime(fpd.RootDir.LastWriteTime)
                };

                static string getPath(string file) =>
                    file.EndsWith(".kkfp") ? (file + "d") : file.EndsWith(".kkfpd") ? file : (file + ".kkfpd");
            }

            for (i = 0; i < c; i++)
                ss[i].Dispose();
        }

        private void Compare(Stream s, KKC[] curses, FilePackerData[] fpds, int index, ref Diff diff)
        {
            int i0, i1, i2, i3;
            bool b0, b1, b2, b3;
            DirData dd0;
            FileData fd0;
            ref FilePackerData fpd = ref fpds[index];

            for (int i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData dd = ref fpd.DirsData[i];
                dd.Index = index;
                b0 = diff.DirStore .ContainsKey(dd.Name, out i0);
                b1 = diff.DirChange.ContainsKey(dd.Name, out i1);
                b2 = diff.DirNoEdit.ContainsKey(dd.Name, out i2);

                dd.Attributes &= 0xFFFFFFF;
                if (b0 || b1 || b2)
                {
                         if (b0) { dd0 = diff.DirStore [i0, true].Value; diff.DirStore .RemoveAt(i0); }
                    else if (b1) { dd0 = diff.DirChange[i1, true].Value; diff.DirChange.RemoveAt(i1); }
                    else         { dd0 = diff.DirNoEdit[i2, true].Value; diff.DirNoEdit.RemoveAt(i2); }

                    if (dd0 != dd)
                    {
                        dd.Attributes |= (uint)DataMode.Change << 28;
                        diff.DirChange.Add(dd.Name, dd);
                    }
                    else
                    {
                        dd.Attributes |= (uint)DataMode.NoEdit << 28;
                        diff.DirNoEdit.Add(dd.Name, dd);
                    }
                }
                else
                {
                    dd.Attributes |= (uint)DataMode.Store << 28;
                    diff.DirStore.Add(dd.Name, dd);
                }
            }

            for (int i = 0; i < diff.DirStore.Count; i++)
            {
                dd0 = diff.DirStore[i, true].Value;
                if (dd0.Index != index) { diff.DirStore.RemoveAt(i); i--; diff.DirDelete.Add(dd0.Name, dd0); }
            }

            for (int i = 0; i < diff.DirChange.Count; i++)
            {
                dd0 = diff.DirChange[i, true].Value;
                if (dd0.Index != index) { diff.DirChange.RemoveAt(i); i--; diff.DirDelete.Add(dd0.Name, dd0); }
            }

            for (int i = 0; i < diff.DirNoEdit.Count; i++)
            {
                dd0 = diff.DirNoEdit[i, true].Value;
                if (dd0.Index != index) { diff.DirNoEdit.RemoveAt(i); i--; diff.DirDelete.Add(dd0.Name, dd0); }
            }

            diff.DirStore .Capacity = diff.DirStore .Count;
            diff.DirChange.Capacity = diff.DirChange.Count;
            diff.DirNoEdit.Capacity = diff.DirNoEdit.Count;
            diff.DirDelete.Capacity = diff.DirDelete.Count;

            for (int i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];
                fd.Index = index;
                b0 = diff.FileStore  .ContainsKey(fd.Name, out i0);
                b1 = diff.FileChange .ContainsKey(fd.Name, out i1);
                b2 = diff.FileReplace.ContainsKey(fd.Name, out i2);
                b3 = diff.FileNoEdit .ContainsKey(fd.Name, out i3);

                if (fd.Hash == 0) { fd.Hash = GetHash(s, fd, curses[index]); fd.OldDataOffset = fd.DataOffset; }

                fd.Attributes &= 0xFFFFFFF;
                if (b0 || b1 || b2 || b3)
                {
                         if (b0) { fd0 = diff.FileStore  [i0, true].Value; diff.FileStore  .RemoveAt(i0); }
                    else if (b1) { fd0 = diff.FileChange [i1, true].Value; diff.FileChange .RemoveAt(i1); }
                    else if (b2) { fd0 = diff.FileReplace[i2, true].Value; diff.FileReplace.RemoveAt(i2); }
                    else         { fd0 = diff.FileNoEdit [i3, true].Value; diff.FileNoEdit .RemoveAt(i3); }

                    if (fd0.Hash != fd.Hash)
                    {
                        fd.Attributes |= (uint)DataMode.Replace << 28;
                        diff.FileReplace.Add(fd.Name, fd);
                    }
                    else if (fd0 != fd)
                    {
                        fd.Attributes |= (uint)DataMode.Change << 28;
                        diff.FileChange.Add(fd.Name, fd);
                    }
                    else
                    {
                        fd.Attributes |= (uint)DataMode.NoEdit << 28;
                        diff.FileNoEdit.Add(fd.Name, fd);
                    }
                }
                else
                {
                    fd.Attributes |= (uint)DataMode.Store << 28;
                    diff.FileStore.Add(fd.Name, fd);
                }
            }

            for (int i = 0; i < diff.FileStore.Count; i++)
            {
                fd0 = diff.FileStore[i, true].Value;
                if (fd0.Index != index) { diff.FileStore.RemoveAt(i); i--; diff.FileDelete.Add(fd0.Name, fd0); }
            }

            for (int i = 0; i < diff.FileChange.Count; i++)
            {
                fd0 = diff.FileChange[i, true].Value;
                if (fd0.Index != index) { diff.FileChange.RemoveAt(i); i--; diff.FileDelete.Add(fd0.Name, fd0); }
            }

            for (int i = 0; i < diff.FileNoEdit.Count; i++)
            {
                fd0 = diff.FileNoEdit[i, true].Value;
                if (fd0.Index != index) { diff.FileNoEdit.RemoveAt(i); i--; diff.FileDelete.Add(fd0.Name, fd0); }
            }

            for (int i = 0; i < diff.FileReplace.Count; i++)
            {
                fd0 = diff.FileReplace[i, true].Value;
                if (fd0.Index != index) { diff.FileReplace.RemoveAt(i); i--; diff.FileDelete.Add(fd0.Name, fd0); }
            }

            diff.FileStore  .Capacity = diff.FileStore  .Count;
            diff.FileChange .Capacity = diff.FileChange .Count;
            diff.FileNoEdit .Capacity = diff.FileNoEdit .Count;
            diff.FileDelete .Capacity = diff.FileDelete .Count;
            diff.FileReplace.Capacity = diff.FileReplace.Count;
        }

        private ulong GetHash(Stream s, FileData fd, KKC curse)
        {
            Console.WriteLine($"Hashing \"{fd.Name}\"");
            long j, l;
            s.PI64 = fd.DataOffset;
            l = fd.DataLength / dA;

            byte[] buf = new byte[dA];
            ulong hash = 0xCBF29CE484222325;
            curse.Reset(fd.IV);
            for (j = 0; j < l; j++)
            {
                s.RBy(dA, buf);
                curse.Decurse(buf, buf);
                hash = buf.CalculateChecksum0(dA, hash);
            }

            l = fd.DataLength - l * dA;
            if (l > 0)
            {
                s.RBy(l.A(hA), buf);
                curse.Decurse(buf, buf);
                hash = buf.CalculateChecksum0(l, hash);
            }
            return hash;
        }

        public struct Diff
        {
            public KKdDict<string,  DirData>  DirStore;
            public KKdDict<string,  DirData>  DirChange;
            public KKdDict<string,  DirData>  DirNoEdit;
            public KKdDict<string,  DirData>  DirDelete;
            public KKdDict<string, FileData> FileStore;
            public KKdDict<string, FileData> FileChange;
            public KKdDict<string, FileData> FileNoEdit;
            public KKdDict<string, FileData> FileDelete;
            public KKdDict<string, FileData> FileReplace;
        }

        public void Repack(string path, string password)
        {
            if (key == null) return;

            key = null;
            KKC curse = default;
            NewKey(ref curse, password);
            if (key == null || curse.Error != 0) return;

            Repack(path, path, curse);
        }

        public void Repack(string path, string path2, string password)
        {
            if (key == null) return;

            key = null;
            KKC curse = default;
            NewKey(ref curse, password);
            if (key == null || curse.Error != 0) return;

            Repack(path, path2, curse);
        }

        public void Repack(string path, byte[] key)
        {
            if (key == null) return;

            this.key = null;
            KKC curse = default;
            NewKey(ref curse, key);
            if (this.key == null || this.curse.Error != 0) return;

            Repack(path, path, curse);
        }

        public void Repack(string path, string path2, byte[] key)
        {
            if (key == null) return;

            this.key = null;
            KKC curse = default;
            NewKey(ref curse, key);
            if (this.key == null || this.curse.Error != 0) return;

            Repack(path, path2, curse);
        }

        private void Repack(string path, string path2, KKC curse2)
        {
            if (key == null || path == null || curse.Error != 0 || curse2.Error != 0) return;

            DataMode dm;
            long i; byte[] h; Stream s;
            FilePackerData fpd = ReadHeader(path, ref curse);
            if (fpd.DataOffset < 0x400 || fpd.DataOffset % 0x400 != 0) return;

            _state = (uint)(fpd.FilesCount + fpd.DirsCount + fpd.NameOffset);
            if (_state == 0) _state = (uint)fpd.NameOffset;
            if (fpd.FilesCount > 0) _state ^= fpd.FilesData[0].IV;

            long[] of = new long[fpd.FilesCount];
            uint[] iv = new uint[fpd.FilesCount];
            for (i = 0; i < fpd.FilesCount; i++)
            { iv[i] = fpd.FilesData[i].IV; fpd.FilesData[i].IV ^= NextRand(); of[i] = fpd.FilesData[i].DataOffset; }

            _state ^= (uint)Environment.TickCount;
            fpd.IV0 = NextRand();
            fpd.IV1 = NextRand();
            fpd.IV2 = NextRand();
            fpd.IV3 = NextRand();

            h = WriteHeader(ref fpd);

            curse2.Reset(fpd.IV0, fpd.IV1, fpd.IV2, fpd.IV3);
            curse2.Curse(h, h, 0x10, 0x10);

            string temp = Path.GetTempFileName();
            Stream s1 = File.OpenWriter(path == path2 ? temp : path2);
            s1.W(h);
            s1.F();
            s = File.OpenReader(path);
            byte[] buf = new byte[dA];
            long j, l;
            s.OI64 = fpd.DataOffset;
            s1.OI64 = fpd.DataOffset;
            for (i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];
                dm = (DataMode)(fd.Attributes >> 28);

                if (dm != DataMode.Store && dm != DataMode.Replace)
                    continue;

                Console.WriteLine($"Packing \"{fd.Name}\"");
                s.PI64 = of[i];
                s1.PI64 = fd.DataOffset;
                l = fd.DataLength / dA;

                curse.Reset(iv[i]);
                curse2.Reset(fd.IV);
                for (j = 0; j < l; j++)
                {
                    s.RBy(dA, buf);
                    curse.Decurse(buf, buf);
                    curse2.Curse(buf, buf);
                    s1.W(buf, dA);
                }

                l = fd.DataLength - l * dA;
                if (l == 0) continue;

                l = l.A(hA);
                s.RBy(l, buf);
                curse.Decurse(buf, buf);
                curse2.Curse(buf, buf);
                s1.W(buf, (int)l);
            }
            s.C();
            s1.C();

            if (path == path2)
            {
                if (File.Exists(path2)) File.Delete(path2);
                File.Move(temp, path2);
            }

            DirData r = fpd.RootDir;
            System.IO.FileInfo ri = new System.IO.FileInfo(path2)
            {
                  CreationTimeUtc = new DateTime(r.LastWriteTime),
                 LastWriteTimeUtc = new DateTime(r.LastWriteTime),
                LastAccessTimeUtc = new DateTime(r.LastWriteTime),
            };
        }

        private FilePackerData ReadHeader(string path, ref KKC curse)
        {
            if (key == null || path == null || curse.Error != 0 || !File.Exists(path)) return default;

            long i;
            Stream s = File.OpenReader(path);
            uint iv0 = s.RU32();
            uint iv1 = s.RU32();
            uint iv2 = s.RU32();
            uint iv3 = s.RU32();
            s.P = 0x0;
            byte[] h = s.RBy(0x30);
            s.C();

            curse.Reset(iv0, iv1, iv2, iv3);
            curse.Decurse(h, h, 0x10, 0x10);

            bool h0 = true, h1 = false;
            for (i = 0; i < 0x10; i++)
                if (header[i] != h[i + 0x10]) { h0 = false; break; }
            if (!h0)
                for (h1 = true, i = 0; i < 0x10; i++)
                    if (headdf[i] != h[i + 0x10]) { h1 = false; break; }
            if (!h0 && !h1) return default;

            s = File.OpenReader(h);
            s.P = 0x20;
            long nameOffset = s.RI64();
            long dataOffset = s.RI64();
            s.C();

            if (nameOffset < 0x1000 || dataOffset < 0x1000) return default;

            s = File.OpenReader(path);
            h = s.RBy(dataOffset);
            s.C();

            curse.Reset(iv0, iv1, iv2, iv3);
            curse.Decurse(h, h, 0x10, 0x10);

            return ReadHeader(h, iv0, iv1, iv2, iv3, h1);
        }

        private FilePackerData ReadHeader(byte[] data, uint iv0, uint iv1, uint iv2, uint iv3, bool diff = false)
        {
            if (data == null || data.Length < 0x30) return default;

            long i;
            FilePackerData fpd;
            Stream s = File.OpenReader(data);
            s.PI64 = 0x20;

            fpd.IV0 = iv0;
            fpd.IV1 = iv1;
            fpd.IV2 = iv2;
            fpd.IV3 = iv3;

            fpd.NameOffset = s.RI64();
            fpd.DataOffset = s.RI64();
            fpd. DirsCount = s.RI64();
            fpd.FilesCount = s.RI64();

            if (!diff) fpd.ParentHash0 = fpd.ParentHash1 = fpd.ParentHash2 = 0;
            else { fpd.ParentHash0 = s.RU64(); fpd.ParentHash1 = s.RU32(); fpd.ParentHash2 = s.RU32(); }


            fpd.RootDir = default;
            fpd. DirsData = new DirData[fpd. DirsCount];
            fpd.FilesData = new       FileData[fpd.FilesCount];

            fpd.RootDir.Unused        = s.RU32();
            fpd.RootDir.Attributes    = s.RU32();
            fpd.RootDir.LastWriteTime = s.RI64();

            for (i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData dd = ref fpd.DirsData[i];
                dd.NameOffset    = s.RI64();
                dd.NameLength    = s.RI64();
                dd.Unused        = s.RU32();
                dd.Attributes    = s.RU32();
                dd.LastWriteTime = s.RI64();
            }

            for (i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];
                fd.NameOffset     = s.RI64();
                fd.NameLength     = s.RI64();
                fd.DataOffset     = s.RI64();
                fd.DataLength     = s.RI64();
                fd.IV             = s.RU32();
                fd.Attributes     = s.RU32();
                fd.  CreationTime = s.RI64();
                fd. LastWriteTime = s.RI64();
                fd.LastAccessTime = s.RI64();
                fd.Hash = 0;
            }

            s.OI64 = fpd.NameOffset;
            System.Text.Encoding e = System.Text.Encoding.Unicode;
            for (i = 0; i < fpd. DirsCount; i++)
                fpd. DirsData[i].Name = e.GetString(s.RBy(fpd. DirsData[i].NameLength, fpd. DirsData[i].NameOffset));
            for (i = 0; i < fpd.FilesCount; i++)
                fpd.FilesData[i].Name = e.GetString(s.RBy(fpd.FilesData[i].NameLength, fpd.FilesData[i].NameOffset));
            s.C();

            fpd.Hash0 = data.CalculateChecksum0(data.LongLength);
            fpd.Hash1 = data.CalculateChecksum1(data.LongLength);
            fpd.Hash2 = data.CalculateChecksum2(data.LongLength);
            return fpd;
        }

        private byte[] WriteHeader(ref FilePackerData fpd, bool diff = false)
        {
            long headLength = (diff ? headdfLength : headerLength) + rootDataLength
                + fpd.DirsCount * 0x20 + fpd.FilesCount * 0x40;
            long nameOffset = headLength.A(hA);
            long dataOffset = nameOffset;

            long i;
            long dO = 0;
            for (i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData dd = ref fpd.DirsData[i];

                dd.NameOffset = dataOffset;
                dataOffset += dd.NameLength = dd.Name.Length * 2;
            }

            DataMode dm;
            for (i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];

                fd.NameOffset = dataOffset;
                dataOffset += fd.NameLength = fd.Name.Length * 2;

                dm = (DataMode)(fpd.FilesData[i].Attributes >> 28);
                if (dm == DataMode.Store || dm == DataMode.Replace)
                {
                    fd.DataOffset = dO;
                    dO += fd.DataLength.A(hA);
                }
            }
            dataOffset = dataOffset.A(hA);

            fpd.NameOffset = nameOffset;
            fpd.DataOffset = dataOffset;

            Stream s = File.OpenWriter();
            s.W(fpd.IV0); s.W(fpd.IV1); s.W(fpd.IV2); s.W(fpd.IV3);
            s.W(diff ? headdf : header);
            s.W(fpd.NameOffset);
            s.W(fpd.DataOffset);
            s.W(fpd. DirsCount);
            s.W(fpd.FilesCount);
            if (diff) { s.W(fpd.ParentHash0); s.W(fpd.ParentHash1); s.W(fpd.ParentHash2); }

            DirData r = fpd.RootDir;
            s.W(r.Unused       );
            s.W(r.Attributes   );
            s.W(r.LastWriteTime);

            for (i = 0; i < fpd.DirsCount; i++)
            {
                ref DirData dd = ref fpd.DirsData[i];

                s.W(dd.NameOffset   );
                s.W(dd.NameLength   );
                s.W(dd.Unused       );
                s.W(dd.Attributes   );
                s.W(dd.LastWriteTime);
            }

            for (i = 0; i < fpd.FilesCount; i++)
            {
                ref FileData fd = ref fpd.FilesData[i];

                s.W(fd.NameOffset    );
                s.W(fd.NameLength    );
                s.W(fd.DataOffset    );
                s.W(fd.DataLength    );
                s.W(fd.IV            );
                s.W(fd.Attributes    );
                s.W(fd.  CreationTime);
                s.W(fd. LastWriteTime);
                s.W(fd.LastAccessTime);
            }
            s.A(fpd.NameOffset, true);

            System.Text.Encoding e = System.Text.Encoding.Unicode;
            for (i = 0; i < fpd. DirsCount; i++)
                s.W(e.GetBytes(fpd. DirsData[i].Name));

            for (i = 0; i < fpd.FilesCount; i++)
                s.W(e.GetBytes(fpd.FilesData[i].Name));
            s.A(fpd.DataOffset, true);
            return s.ToArray();
        }

        private static T[] MergeWith<T>(T[] array1, T[] array2)
        {
            int length1 = array1.Length;
            int length2 = array2.Length;
            T[] array = new T[length1 + length2];
            Array.Copy(array1, 0, array,       0, length1);
            Array.Copy(array2, 0, array, length1, length2);
            return array;
        }

        public void Dispose()
        { curse.Dispose(); key = null; }

        public struct FilePackerData
        {
            public uint IV0;
            public uint IV1;
            public uint IV2;
            public uint IV3;
            public long  DirsCount;
            public long FilesCount;
            public DirData RootDir;
            public DirData[]  DirsData;
            public       FileData[] FilesData;

            public ulong Hash0;
            public  uint Hash1;
            public  uint Hash2;

            public ulong ParentHash0;
            public  uint ParentHash1;
            public  uint ParentHash2;

            public long NameOffset;
            public long DataOffset;

            public override string ToString() =>
                $"(Root Dir: {RootDir}; Dirs Count: {DirsCount}; Files Count: {FilesCount}"
                + $"; Hash 0: 0x{Hash0:X16}; Hash 1: 0x{Hash1:X8}; Hash 2: 0x{Hash2:X8})";
        }

        public struct DirData
        {
            public long NameOffset;
            public long NameLength;
            public uint Unused;
            public uint Attributes;
            public long LastWriteTime;

            public string Name;

            public int Index;

            public static bool operator ==(DirData a, DirData b) =>
                a.Attributes == b.Attributes && a.LastWriteTime == b.LastWriteTime && a.Name == b.Name;
            public static bool operator !=(DirData a, DirData b) =>
                a.Attributes != b.Attributes || a.LastWriteTime != b.LastWriteTime || a.Name != b.Name;

            public override bool Equals(object obj) =>
                obj is DirData dd && dd == this;

            public override int GetHashCode() =>
                base.GetHashCode();

            public override string ToString() =>
                $"({(Name != null && Name != "" ? $"Name: {Name}; " : "")}" +
                $"Data Mode: {(DataMode)(Attributes >> 28)}" +
                $"; Last Write Time: {new DateTime(LastWriteTime)})";
        }

        public struct FileData
        {
            public long NameOffset;
            public long NameLength;
            public long DataOffset;
            public long DataLength;
            public uint IV;
            public uint Attributes;
            public long   CreationTime;
            public long  LastWriteTime;
            public long LastAccessTime;

            public string Name;

            public int Index;
            public ulong Hash;
            public long OldDataOffset;

            public static bool operator ==(FileData a, FileData b) =>
                a.Attributes == b.Attributes && a.CreationTime == b.CreationTime && a.LastWriteTime
                == b.LastWriteTime && a.LastAccessTime == b.LastAccessTime && a.Name == b.Name;
            public static bool operator !=(FileData a, FileData b) =>
                a.Attributes != b.Attributes || a.CreationTime != b.CreationTime || a.LastWriteTime
                != b.LastWriteTime || a.LastAccessTime != b.LastAccessTime || a.Name != b.Name;

            public override bool Equals(object obj) =>
                obj is FileData fd && fd == this;

            public override int GetHashCode() =>
                base.GetHashCode();

            public override string ToString() =>
                $"(Name: {Name}; Data Mode: {(DataMode)(Attributes >> 28)}" +
                $"; Creation Time: {new DateTime(CreationTime)}" +
                $"; Last Write Time: {new DateTime(LastWriteTime)}" +
                $"; Last Access Time: {new DateTime(LastAccessTime)})";
        }

        public enum DataMode : byte
        {
            Store   = 0,
            Change  = 1,
            NoEdit  = 2,
            Delete  = 3,
            Replace = 4,
        }
    }
}
