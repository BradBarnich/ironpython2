using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Scripting.Runtime;

using IronPython.Runtime;
using IronPython.Runtime.Operations;


//[assembly: PythonModule("_hashlib", typeof(IronPython.Modules.PythonHashlib))]
namespace IronPython.Modules {
    
    [PythonHidden]
    public abstract class HashBase<T>
#if FEATURE_ICLONEABLE
            : ICloneable
#endif
            where T : HashAlgorithm {

        protected T _hasher;
        private readonly List<byte> _data = new List<byte>();

        private static readonly Encoding _raw = Encoding.GetEncoding("iso-8859-1");
        private static readonly byte[] _empty = _raw.GetBytes(string.Empty);

        public readonly string name;
        public readonly int block_size;
        public readonly int digest_size;
        public readonly int digestsize;

        internal HashBase(string name, int blocksize, int digestsize) {
            this.name = name;
            this.block_size = blocksize;
            this.digest_size = this.digestsize = digestsize;
            CreateHasher();
        }

        protected abstract void CreateHasher();

        public void update(Bytes newBytes) {
            update((IList<byte>)newBytes);
        }

        public void update(ByteArray newBytes) {
            update((IList<byte>)newBytes);
        }

        [Documentation("update(string) -> None (update digest with string data)")]
        public void update(object newData) {
            ArrayModule.array a = newData as ArrayModule.array;
            if (a != null) {
                update(a.ToByteArray());
            } else {
                update(Converter.ConvertToString(newData).MakeByteArray());
            }
        }

        public void update(PythonBuffer buffer) {
            update((IList<byte>)buffer);
        }

        internal void update(IList<byte> newBytes) {
            byte[] bytes = newBytes.ToArray();
            lock (_hasher) {
                _data.AddRange(bytes);
                _hasher.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
            }
        }

        [Documentation("digest() -> int (current digest value)")]
        public string digest() {
            T copy = CloneHasher();
            copy.TransformFinalBlock(_empty, 0, 0);
            return copy.Hash.MakeString();
        }

        [Documentation("hexdigest() -> string (current digest as hex digits)")]
        public string hexdigest() {
            T copy = CloneHasher();
            copy.TransformFinalBlock(_empty, 0, 0);

            StringBuilder result = new StringBuilder(2 * copy.Hash.Length);
            for (int i = 0; i < copy.Hash.Length; i++) {
                result.Append(copy.Hash[i].ToString("x2"));
            }
            return result.ToString();
        }

        public abstract HashBase<T> copy();

#if FEATURE_ICLONEABLE
        object ICloneable.Clone() {
            return copy();
        }
#endif

        protected void CopyStateFrom(HashBase<T> other) {
            byte[] bytes;
            lock (other._hasher) {
                bytes = other._data.ToArray();
            }

            lock (_hasher) {
                _data.Clear();
                _data.AddRange(bytes);
                _hasher.Initialize();
                _hasher.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
            }
        }

        protected T CloneHasher() {
            byte[] bytes;
            Type hasherType;
            lock (_hasher) {
                bytes = _data.ToArray();
                hasherType = _hasher.GetType();
            }

            T clone = (T)Activator.CreateInstance(hasherType);
            clone.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
            return clone;
        }
    }
}
