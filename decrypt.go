package decrypt

import "io"

//Decrypting reader struct to automatically xor bytes with a key
//in a circular fashion
type DecryptingReader struct {
	key string
	n   int
	r   io.Reader
}

//Implement the Read method automatically decrypting with the key
func (d *DecryptingReader) Read(p []byte) (n int, err error) {
	n, err = d.r.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= d.key[d.n]
		d.n = (d.n + 1) % len(d.key)
	}
	return
}

//Reset our key offset
func (d *DecryptingReader) Reset() {
	d.n = 0
}

//Creates a new DecryptingReader
func New(key string, r io.Reader) *DecryptingReader {
	return &DecryptingReader{key: key, r: r}
}
