# Ionic3 Usage

This provider can be used in any Ionic application :)

## Installation
Make sure, you're inside your ionic-project's folder.

Then run:
```bash
$ ionic generate provider sha2
```

Now, open your newly generated provider and replace it's code with `sha2.ts` `s code which you can find in this folder.

## Usage
Now, on any page, add:
```typescript
import {Sha2Provider} from "../../providers/sha2/sha2";

...

constructor(..., private sha2: Sha2Provider) {}

ionViewDidLoad() {
    ...
    console.log(this.sha2.SHA2_512('hello'));
}

...
```

*Thanks a lot to @markvandenbrink for writing this initially in normal Typescript!*
