**Alpine Type Data Documentation**

This document notes additional information (beyond that found in the Alpine schema) about the values associated with
each field such as the format in which the data is stored and any necessary transformations.

Further information about pkginfo fields and the .PKGINFO file can be found on the [Alpine documentation website](https://wiki.alpinelinux.org/wiki/Alpine_package_format#.PKGINFO).

The value of the `publicKey` `content` field ought to be Base64-encoded.

**How do you identify an object as an Alpine object?**

The "Body" field will include an "AlpineModel" field.
