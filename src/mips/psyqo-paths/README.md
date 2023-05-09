While the [PSYQo](../psyqo) library is still very light, and not really opinionated on how to process certain operations, it means it can be tedious and verbose to write certain things. This is where the PSYQo Paths library comes in: it provides a set of functions called "Paths" to help with common operations, such as loading a file from CD-Rom.

The point is to provide a set of functions that are easy to use, but are also too generic to be included in the PSYQo library itself. Using them comes with the caveat that they are not optimized for any specific use case, and may not be the best solution for your specific problem. However, they should be good enough for most cases, and can be used as a starting point for more specific implementations.

## Loading a file from CD-Rom

This Path will allow you to load a file from CD-Rom, and return a vector containing the file's data. As with the rest of PSYQo, the loading is still going to be done asynchronously, so you will need to either pass a callback to the class' method, or use the `schedule` version of the method using the task scheduler.

See [the example](examples/cdrom-loader) for a full usage example.
