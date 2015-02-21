# TypeScript SHA2 Module
This is a pretty fast SHA2 implementation written in TypeScript. It implements the complete SHA-2 family with digests that are 224, 256, 384 or 512 bits: SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256.

## Usage

Import the module:

```typescript
import SHA2 = require("sha2");
```

And start hashing...

```typescript
SHA2.SHA2_224(""); // Returns "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
SHA2.SHA2_256(""); // Returns "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA2.SHA2_384(""); // Returns "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
SHA2.SHA2_512(""); // Returns "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
SHA2.SHA2_512_224(""); // Returns "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
SHA2.SHA2_512_256(""); // Returns "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
```

## More information
http://en.wikipedia.org/wiki/SHA-2

## License
This module is licensed under the [MIT license](http://www.opensource.org/licenses/MIT).
