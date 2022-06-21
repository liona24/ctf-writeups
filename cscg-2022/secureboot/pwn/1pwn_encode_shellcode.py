import subprocess


class Encoder():
    def __init__(self, codeBaseAddress):
        self.codeBaseAddress = codeBaseAddress
        self.i = 0

        self.decoderSize = 0
        self.decodeInstructions = []
        self.encodedBytes = []

    def is_good_byte(self, b: int):
        badBytes = [ ord('\n'), ord('\r') ]
        # if 0 < b and b < 0x7f and b not in badBytes:
        if 0x0 < b and b < 0x7f and b not in badBytes:
            return True
        else:
            return False

    def encode_one_byte(self, b: int):
        if self.is_good_byte(b):
            # nothing to do
            self.encodedBytes.append(b)
            self.i += 1
            return
        else:
            # bruteforce for the win
            for dl in range(1, 0x7f):
                if not self.is_good_byte(dl):
                    continue

                for encodedByte in range(1, 0x7f):
                    if not self.is_good_byte(encodedByte):
                        continue

                    if (encodedByte - dl) & 0xFF == b:
                        dx = 0x4100 | dl
                        self.encodedBytes.append(encodedByte)
                        self.decodeInstructions.append(f"push {hex(dx)}")
                        self.decodeInstructions.append(f"pop dx")
                        self.decodeInstructions.append(f"sub byte [{hex(self.codeBaseAddress + self.i)}], dl")
                        self.decodeInstructions.append("") # visuals
                        self.decoderSize += 8
                        self.i += 1
                        return
                    elif (encodedByte - dl - dl) & 0xFF == b:
                        dx = 0x4100 | dl
                        self.encodedBytes.append(encodedByte)
                        self.decodeInstructions.append(f"push {hex(dx)}")
                        self.decodeInstructions.append(f"pop dx")
                        self.decodeInstructions.append(f"sub byte [{hex(self.codeBaseAddress + self.i)}], dl")
                        self.decodeInstructions.append(f"sub byte [{hex(self.codeBaseAddress + self.i)}], dl")
                        self.decodeInstructions.append("") # visuals
                        self.decoderSize += 12
                        self.i += 1
                        return

        raise ValueError(f"Could not encode byte {hex(b)} at position {self.i}")

    def compile(self, decoderBaseAddr):
        fillInstr = 0x47 # inc di

        with open("decoder.asm", "w") as fout:
            print("[bits 16]", file=fout)
            print(f"[org {hex(decoderBaseAddr)}]", file=fout)
            for ins in self.decodeInstructions:
                print(ins, file=fout)

            spaceRemaining = self.codeBaseAddress - decoderBaseAddr - self.decoderSize
            assert spaceRemaining >= 0, f"Decoder too large. Overriding encoded bytes! {hex(decoderBaseAddr)} + {self.decoderSize}"

            print("", file=fout)
            print("; padding", file=fout)
            for _ in range(spaceRemaining):
                print(f"db {hex(fillInstr)}", file=fout)

            print("", file=fout)
            print("; encoded data section", file=fout)
            for b in self.encodedBytes:
                print(f"db {hex(b)}", file=fout)

        subprocess.run(["nasm", "-f", "bin", "decoder.asm", "-o", "decoder.bin"], check=True)
        with open("decoder.bin", "rb") as fin:
            return fin.read()


decoderBase = 0x7021

# skip bad bytes in LSB
codeBase = 0x7121

with open("1pwn_dump_flag.bin", "rb") as fin:
    code = fin.read()

enc = Encoder(codeBase)
for byte in code:
    enc.encode_one_byte(byte)

with open("1pwn_dump_flag.bin.encoded", "wb") as fout:
    fout.write(enc.compile(decoderBase))
