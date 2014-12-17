Symbolicator
by Peter Hosey

This is a program to symbolicate crash logs generated on Mac OS X.

When you receive a crash log, pipe it through the Symbolicator. You'll probably want to send the output into a pager or editor.

	symbolicator < MyApp-2009-01-01-130145_My-Computer.crash | less 

The Symbolicator will use Spotlight to find any dSYM bundles it needs, and dwarfdump to extract symbol information for the addresses in the crash log; it will then replace the bare addresses in the log text with the matching symbol information, and write the symbolicated text out to its standard output.

This means:

- You do not need to tell the Symbolicator where your dSYM bundles are, nor to put your dSYM bundles into a special location. As long as Spotlight can find them, the Symbolicator will find them automatically.
- You can use ThisService (http://wafflesoftware.net/thisservice/) to make a Symbolicator service. With this, you can select the entire text of a crash log, use your preferred graphical editor's New Window with Selection service to copy that text to a new document, and then select the crash log text there and run your Symbolicator service on it.
