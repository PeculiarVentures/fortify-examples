# Fortify Desktop Application

Fortify enables web applications to use smart cards, local certificate stores and do certificate enrollment. This repository contains examples on how to use it to add support for Fortify to your own applications.

## Examples

| Example                                                                                               |
| ----------------------------------------------------------------------------------------------------- |
| [Certificate request generation](https://peculiarventures.github.io/fortify-examples/example1.html)   |
| [Importing a certificate](https://peculiarventures.github.io/fortify-examples/example2.html)          |
| [Create a self signed certificate](https://peculiarventures.github.io/fortify-examples/example3.html) |
| [Provider enumeration](https://peculiarventures.github.io/fortify-examples/example4.html)             |
| [Signing](https://peculiarventures.github.io/fortify-examples/example5.html)                          |
| [Certificate chain building](https://peculiarventures.github.io/fortify-examples/example6.html)       |
| [Data encryption/decryption](https://peculiarventures.github.io/fortify-examples/example7.html)       |

## Development

To run the examples locally, you can use the following commands:

```bash
npx node-static -H '{"Cache-Control": "no-cache, must-revalidate"}'
```

## Thanks

Thanks to the [CA Security Council](https://casecurity.org/) for their support of this project and the many individuals from [Twitter](https://twitter.com/rmhrisk) who provided feedback and testing.
