package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type OpCodeType int

const (
	ImmToReg OpCodeType = iota
	ImmToRegModRM
	RegToReg
)

type Inst int

func (i Inst) String() string {
	switch i {
	case Mov:
		return "MOV"
	case Xor:
		return "XOR"
	case Add:
		return "ADD"
	}
	return "UNKNOWN INST"
}

const (
	Mov Inst = iota
	Xor
	Add
)

type OpCode struct {
	Code      byte
	RegCode   byte
	Type      OpCodeType
	Inst      Inst
	UsesModRM bool
	Size      int
}

var opCodes = []OpCode{
	{0xb8, 0, ImmToReg, Mov, false, 0},
	{0x89, 0, RegToReg, Mov, true, 0},
	{0x83, 0, ImmToRegModRM, Add, true, 1},
	{0x81, 0, ImmToRegModRM, Xor, true, 4},
	{0x83, 0x6, ImmToRegModRM, Xor, true, 1},
	{0x31, 0, RegToReg, Xor, true, 0},
}

func findOpCode(b, reg byte) (OpCode, error) {
	foundOpCodes := []OpCode{}
	for _, o := range opCodes {
		if o.UsesModRM && o.Code == b {
			foundOpCodes = append(foundOpCodes, o)
		} else if o.Code&b == o.Code {
			foundOpCodes = append(foundOpCodes, o)
		}
	}
	switch len(foundOpCodes) {
	case 0:
		return OpCode{}, fmt.Errorf("unknown opcode 0x%x", b)
	case 1:
		return foundOpCodes[0], nil
	default:
		// This is very hacky and unsure how else to do this.
		// There is some scenarios, like 'and' and 'xor' that
		// are only distinguised by the 'reg' byte in the 'modrm',
		// and the only way to check that is to read ahead of the current
		// identifying byte, assume the next byte is a 'modrm' byte and
		// check against that.
		//
		// TODO: I am exceptionally unsure if this will return the
		// correct result...
		mostLikelyOpCode := foundOpCodes[0]
		for _, o := range foundOpCodes {
			if o.RegCode > 0 && o.RegCode == reg {
				return o, nil
			} else if mostLikelyOpCode.RegCode > o.RegCode {
				mostLikelyOpCode = o
			}
		}
		return mostLikelyOpCode, nil
	}
}

func main() {
	fmt.Println("Readelf...")
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Printf("requires a filename\n")
		os.Exit(1)
	}
	filename := flag.Args()[0]

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	r := bytes.NewReader(data)
	e, err := elf.NewFile(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", e)
	for _, prog := range e.Progs {
		fmt.Printf("%#v\n", prog)
		buf := make([]byte, prog.Memsz)
		n, err := prog.Open().Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		var start uint64
		if buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
			// Apparently the ELF header can contain assembly?
			start = e.Entry - prog.Vaddr
		}
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X == elf.PF_X) {
			if err := parseExecProg(buf[int(start):], os.Stdout); err != nil {
				log.Fatal(err)
			}
			continue
		}
		fmt.Println(n, buf)
	}
}

type Decoder struct {
	Data   []byte
	output io.Writer

	i      int
	startI int
	rex    REX
	modrm  ModRM
}

func parseExecProg(data []byte, output io.Writer) error {
	d := &Decoder{Data: data, output: output}
	/*
		REX (0-1 bytes) | Opcode (1-3 bytes) | MODR/M (0 -1 bytes) | SIB (0-1 bytes) | Displacement (0, 1, 2 or 4 bytes) | Immediate (0, 1, 2 or 4 bytes)
	*/
	d.i = 0
	for {
		if d.i >= len(d.Data) {
			return nil
		}
		if d.Data[d.i] == 0x0f && d.Data[d.i+1] == 0x05 {
			fmt.Fprintf(d.output, "SYSCALL\n")
			d.i += 2
			continue
		}
		d.startI = d.i
		d.rex = REX{}
		d.modrm = ModRM{}
		opCodeByte := d.Data[d.i]
		d.parseREX()
		if d.rex.Valid {
			opCodeByte = d.Data[d.i]
			d.i++
			d.parseModRM()
		} else {
			d.i++
		}
		opCode, err := findOpCode(opCodeByte, d.modrm.Reg)
		if err != nil {
			return err
		}
		if d.rex.Valid && opCode.UsesModRM {
			// Assume we have used the modrm byte
			d.i++
		}
		switch opCode.Type {
		case ImmToReg:
			d.handleImmToReg(opCode, opCodeByte)
		case ImmToRegModRM:
			d.handleImmToRegModRM(opCode)
		case RegToReg:
			d.handleRegToReg(opCode)
		default:
			return fmt.Errorf("unhandled opcode type: %d (0x%x)\n", d.Data[d.i], d.Data[d.i])
		}
	}
	return nil
}

func (d *Decoder) handleImmToReg(o OpCode, opCodeByte byte) {
	reg := opCodeByte - o.Code
	fmt.Fprintf(d.output, "%s %s, 0x%x\n", o.Inst, d.formatReg(reg, d.rex.B), d.formatBytes(d.Data[d.i:d.i+d.rex.BytesToRead()]))
	d.i += d.rex.BytesToRead()
}

func (d *Decoder) handleImmToRegModRM(o OpCode) {
	regSrc := d.modrm.RM
	fmt.Fprintf(d.output, "%s %s, 0x%x\n", o.Inst, d.formatReg(regSrc, d.rex.B), d.formatBytes(d.Data[d.i:d.i+o.Size]))
	d.i += o.Size
}

func (d *Decoder) handleRegToReg(o OpCode) {
	regDst := d.modrm.Reg
	regSrc := d.modrm.RM
	fmt.Fprintf(d.output, "%s %s, %s\n", o.Inst, d.formatReg(regSrc, d.rex.B), d.formatReg(regDst, d.rex.R))
}

func (d *Decoder) formatBytes(b []byte) []byte {
	l := len(b)
	if l == 1 {
		return b
	}
	bigEndianB := make([]byte, l)
	// Convert little endian to big endian. Likely
	// not the best way to do this.
	for i := l - 1; i > 0; i -= 2 {
		bigEndianB[l-i-1] = b[i]
		bigEndianB[(l-i-1)+1] = b[i-1]
	}
	// Return from first non-0 byte index
	for i, c := range bigEndianB {
		if c != 0x00 {
			return bigEndianB[i:]
		}
	}
	return bigEndianB
}

func (d *Decoder) formatReg(reg byte, ext bool) string {
	var regString string
	if !ext {
		switch reg {
		case 0:
			regString = "rax"
		case 1:
			regString = "rcx"
		case 2:
			regString = "rdx"
		case 3:
			regString = "rbx"
		case 4:
			regString = "rsp"
		case 5:
			regString = "rbp"
		case 6:
			regString = "rsi"
		case 7:
			regString = "rdi"
		case 8:
			regString = "r8"
		case 9:
			regString = "r9"
		case 10:
			regString = "r10"
		case 11:
			regString = "r11"
		case 12:
			regString = "r12"
		case 13:
			regString = "r13"
		case 14:
			regString = "r14"
		case 15:
			regString = "r15"
		}
	} else {
		switch reg {
		case 0:
			regString = "r8"
		case 1:
			regString = "r9"
		case 2:
			regString = "r10"
		case 3:
			regString = "r11"
		case 4:
			regString = "r12"
		case 5:
			regString = "r13"
		case 6:
			regString = "r14"
		case 7:
			regString = "r15"
		}
	}
	return regString
}

type REX struct {
	Valid bool
	W     bool
	R     bool
	X     bool
	B     bool
}

func (r REX) BytesToRead() int {
	if r.W {
		return 8
	} else {
		return 4
	}
}

func (d *Decoder) parseREX() {
	/*
		The REX prefix is only available in long mode. An REX prefix must be encoded when:

		using 64-bit operand size and the instruction does not default to 64-bit operand size
		using one of the extended registers (R8 to R15, XMM8 to XMM15, YMM8 to YMM15, CR8 to CR15 and DR8 to DR15)
		using one of the uniform byte registers SPL, BPL, SIL or DIL

		REX Encoding
		| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
		| 0   1   0   0 | W | R | X | B |
		0100 is a 4 bit fixed bit pattern.
		W (1 bit): 1 when a 64-bit operand size is used. Otherwise, 0 will use the default 32-bit operand size.
		R (1 bit): Extension of MODRM.reg field.
		X (1 bit): Extension of SIB.index field.
		B (1 bit): Entension of MODRM.rm or SIB.base field.
	*/
	b := d.Data[d.i]
	if b&(1<<7) == 0 && b&(1<<6) == 1<<6 && b&(1<<5) == 0 && b&(1<<4) == 0 {
	} else {
		d.rex = REX{}
		return
	}
	d.rex = REX{
		Valid: true,
		W:     b&(1<<3) >= 1,
		R:     b&(1<<2) >= 1,
		X:     b&(1<<1) >= 1,
		B:     b&(1<<0) >= 1,
	}
	d.i++
}

type ModRM struct {
	Mod byte
	Reg byte
	RM  byte
}

func (d *Decoder) parseModRM() {
	//
	//	MODRM.mod (2 bits):
	//	00 -> [rax]
	//	01 -> [rax + imm8], an immediate / constant 8 bit value
	//	10 -> [rax + imm32], an immediate / constant 32 bit value
	//	11 -> rax
	//
	b := d.Data[d.i]
	mod := (b & ((1 << 7) + (1 << 6))) >> 6
	reg := (b & ((1 << 5) + (1 << 4) + (1 << 3))) >> 3
	rm := b & ((1 << 2) + (1 << 1) + (1 << 0))
	d.modrm = ModRM{
		Mod: mod,
		Reg: reg,
		RM:  rm,
	}
	// NOTE: We do not increment d.i by 1 since we need to
	// do a look ahead check for a modrm, but it may not actually
	// be valid or used.
}
