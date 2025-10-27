- `msg.enc`
```bash
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921
```
- `chall.py`
```python
import string
from secret import MSG

def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)

ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close()
```

---
- in python:
```python
import math
with open('msg.enc','r') as enc_file:
    enc_string = enc_file.read()
    enc_bytes = bytes.fromhex(enc_string)
    enc_list = list(enc_bytes)
    # print(enc_list)
    dec_list = []
    for enc_dig in enc_list:
        i = 1
        while True:
            temp = ((enc_dig+(256*i)) - 18 )/123
            if math.floor(temp) == temp:
                dec_list.append(temp)
                break
            i += 1
    for i in dec_list:
        print(chr(int(i)),end='')
```
- in rust
```rust
use std::fs;
fn main() {
    let hex = hex::decode(fs::read_to_string("msg.enc").unwrap().trim_end()).unwrap();
    let msg_dec = hex
        .iter()
        .map(|x| {
            let mut i = 0;
            loop {
                let temp: f64 = ((*x as f64 + (256f64 *i as f64)) - 18f64)/123f64;
                if temp.round() == temp {
                    return temp as u8 as char;
                }
                i += 1;
            }
        })
        .collect::<String>();
    println!("{}", msg_dec);
}
```
### flag
```bash
Th3 nucl34r w1ll 4rr1v3 0n fr1d4y.
HTB{l00k_47_y0u_r3v3rs1ng_3qu4710n5_c0ngr475}
```