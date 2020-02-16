package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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
	case Syscall:
		return "SYSCALL"
	}
	return "UNKNOWN INST"
}

const (
	Mov Inst = iota
	Xor
	Add
	Syscall
)

type OpCode struct {
	Code      byte
	RegCode   byte
	Type      OpCodeType
	Inst      Inst
	UsesModRM bool
	Size      int
}

func (o OpCode) String() string {
	return o.Inst.String()
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

type Register int

const (
	RUnknown Register = iota
	RAX
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

func (r Register) String() string {
	switch r {
	case RAX:
		return "rax"
	case RCX:
		return "rcx"
	case RDX:
		return "rdx"
	case RBX:
		return "rbx"
	case RSP:
		return "rsp"
	case RBP:
		return "rbp"
	case RSI:
		return "rsi"
	case RDI:
		return "rdi"
	case R8:
		return "r8"
	case R9:
		return "r9"
	case R10:
		return "r10"
	case R11:
		return "r11"
	case R12:
		return "r12"
	case R13:
		return "r13"
	case R14:
		return "r14"
	case R15:
		return "r15"
	}
	return "unknown register"
}

type IR struct {
	opCode        OpCode
	regSrc        Register
	regDst        Register
	imm           uint64
	indexPosition int
}

func (ir IR) String() string {
	s := fmt.Sprintf("0x%x) %s", ir.indexPosition, ir.opCode)
	if ir.regDst != RUnknown && ir.regSrc != RUnknown {
		s += fmt.Sprintf(" %s, %s", ir.regDst, ir.regSrc)
	} else if ir.regDst != RUnknown && ir.regSrc == RUnknown {
		s += fmt.Sprintf(" %s, 0x%x", ir.regDst, ir.imm)
	}
	return s
}

type Program struct {
	file         *elf.File
	irSection    Section
	dataSections []Section
}

func NewProgram(e *elf.File) *Program {
	return &Program{file: e, dataSections: []Section{}}
}

func (p *Program) addIRSection(s Section) {
	// TODO: This should error
	p.irSection = s
}

func (p *Program) addDataSection(s Section) {
	p.dataSections = append(p.dataSections, s)
}

type programState struct {
	exit     bool
	exitCode uint64

	dataSections []Section

	rax uint64
	rcx uint64
	rdx uint64
	rbx uint64
	rsp uint64
	rbp uint64
	rsi uint64
	rdi uint64
	r8  uint64
	r9  uint64
	r10 uint64
	r11 uint64
	r12 uint64
	r13 uint64
	r14 uint64
	r15 uint64
}

func (ps *programState) getRegister(reg Register) uint64 {
	switch reg {
	case RAX:
		return ps.rax
	case RCX:
		return ps.rcx
	case RDX:
		return ps.rdx
	case RBX:
		return ps.rbx
	case RSP:
		return ps.rsp
	case RBP:
		return ps.rbp
	case RSI:
		return ps.rsi
	case RDI:
		return ps.rdi
	case R8:
		return ps.r8
	case R9:
		return ps.r9
	case R10:
		return ps.r10
	case R11:
		return ps.r11
	case R12:
		return ps.r12
	case R13:
		return ps.r13
	case R14:
		return ps.r14
	case R15:
		return ps.r15
	}
	return 0
}
func (ps *programState) updateRegister(reg Register, data uint64) {
	switch reg {
	case RAX:
		ps.rax = data
	case RCX:
		ps.rcx = data
	case RDX:
		ps.rdx = data
	case RBX:
		ps.rbx = data
	case RSP:
		ps.rsp = data
	case RBP:
		ps.rbp = data
	case RSI:
		ps.rsi = data
	case RDI:
		ps.rdi = data
	case R8:
		ps.r8 = data
	case R9:
		ps.r9 = data
	case R10:
		ps.r10 = data
	case R11:
		ps.r11 = data
	case R12:
		ps.r12 = data
	case R13:
		ps.r13 = data
	case R14:
		ps.r14 = data
	case R15:
		ps.r15 = data
	}
}
func (ps *programState) handleSyscall() {
	switch ps.rax {
	case 0x01:
		// SYS_WRITE
		// fd := ps.getRegister(RDI) // Ignore the stdout/err for now
		l := ps.getRegister(RDX)
		dataIndex := ps.getRegister(RSI)
		data := ps.getData(dataIndex, l)
		fmt.Printf("%s", data)
		ps.updateRegister(RAX, l)
	case 0x3c:
		// SYS_EXIT
		ps.exit = true
		ps.exitCode = ps.getRegister(RDI)
	default:
		fmt.Printf("[WARN] unknown syscall 0x%x\n", ps.rax)
	}
}

func (ps *programState) getData(index, length uint64) []byte {
	for _, ds := range ps.dataSections {
		if index >= ds.elfProg.Vaddr && index < ds.elfProg.Vaddr+ds.elfProg.Memsz {
			dataIndex := int(index - ds.elfProg.Vaddr)
			return ds.data[dataIndex : dataIndex+int(length)]
		}
	}
	return nil
}

func (p *Program) run() {
	for _, d := range p.dataSections {
		// TODO: For now just don't print the elf header. It could be
		// possible that data is in the elf header and should be printed out,
		// but I have no idea how to handle this at the moment.
		if d.isElfHeader {
			continue
		}
		fmt.Printf("0x%x", d.elfProg.Vaddr)
		for _, b := range d.data {
			fmt.Printf(" 0x%x|%d|%q", b, b, b)
		}
		fmt.Println()
	}
	for _, ir := range p.irSection.irs {
		fmt.Printf("%v\n", ir)
	}
	fmt.Println()
	fmt.Println()
	state := programState{dataSections: p.dataSections}
	for _, ir := range p.irSection.irs {
		if state.exit {
			break
		}
		switch ir.opCode.Inst {
		case Syscall:
			state.handleSyscall()
		case Mov:
			var data uint64
			if ir.regSrc == RUnknown {
				data = ir.imm
			} else {
				data = state.getRegister(ir.regSrc)
			}
			state.updateRegister(ir.regDst, data)
		case Xor:
			regDst := state.getRegister(ir.regDst)
			regSrc := state.getRegister(ir.regSrc)
			state.updateRegister(ir.regDst, regDst^regSrc)
		}
	}
	fmt.Printf("\n\nexiting, code=%d\n", state.exitCode)
}

type Section struct {
	elfProg     *elf.Prog
	isElfHeader bool
	irs         []IR
	data        []byte
}

func main() {
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
	program := NewProgram(e)
	for _, prog := range e.Progs {
		buf := make([]byte, prog.Memsz)
		_, err := prog.Open().Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		var start uint64
		isElfHeader := false
		if buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
			// Apparently the ELF header can contain assembly?
			start = e.Entry - prog.Vaddr
			isElfHeader = true
		}
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X == elf.PF_X) {
			irs, err := parseExecProg(buf[int(start):], os.Stdout)
			if err != nil {
				log.Fatal(err)
			}
			program.addIRSection(Section{elfProg: prog, irs: irs, isElfHeader: isElfHeader})
		} else if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_R == elf.PF_R) {
			program.addDataSection(Section{elfProg: prog, data: buf, isElfHeader: isElfHeader})
		}
	}
	program.run()
}

type Decoder struct {
	Data   []byte
	output io.Writer
	irs    []IR

	i      int
	startI int
	rex    REX
	modrm  ModRM
}

func parseExecProg(data []byte, output io.Writer) ([]IR, error) {
	d := &Decoder{Data: data, output: output}
	/*
		REX (0-1 bytes) | Opcode (1-3 bytes) | MODR/M (0 -1 bytes) | SIB (0-1 bytes) | Displacement (0, 1, 2 or 4 bytes) | Immediate (0, 1, 2 or 4 bytes)
	*/
	d.i = 0
	for {
		if d.i >= len(d.Data) {
			break
		}
		if d.Data[d.i] == 0x0f && d.Data[d.i+1] == 0x05 {
			d.irs = append(d.irs, IR{
				opCode:        OpCode{Inst: Syscall},
				indexPosition: d.i,
			})
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
			return nil, err
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
			return nil, fmt.Errorf("unhandled opcode type: %d (0x%x)", d.Data[d.i], d.Data[d.i])
		}
	}

	return d.irs, nil
}

func (d *Decoder) handleImmToReg(o OpCode, opCodeByte byte) {
	regDstByte := opCodeByte - o.Code
	regDst := d.getReg(regDstByte, d.rex.B)
	d.irs = append(d.irs, IR{
		opCode:        o,
		regDst:        regDst,
		imm:           d.binaryFromBytes(d.Data[d.i : d.i+d.rex.BytesToRead()]),
		indexPosition: d.startI,
	})
	d.i += d.rex.BytesToRead()
}

func (d *Decoder) handleImmToRegModRM(o OpCode) {
	regDstByte := d.modrm.RM
	regDst := d.getReg(regDstByte, d.rex.B)
	d.irs = append(d.irs, IR{
		opCode:        o,
		regDst:        regDst,
		imm:           d.binaryFromBytes(d.Data[d.i : d.i+o.Size]),
		indexPosition: d.startI,
	})
	d.i += o.Size
}

func (d *Decoder) handleRegToReg(o OpCode) {
	regDstByte := d.modrm.Reg
	regDst := d.getReg(regDstByte, d.rex.R)
	regSrcByte := d.modrm.RM
	regSrc := d.getReg(regSrcByte, d.rex.B)
	d.irs = append(d.irs, IR{
		opCode:        o,
		regSrc:        regSrc,
		regDst:        regDst,
		indexPosition: d.startI,
	})
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

func (d *Decoder) binaryFromBytes(b []byte) uint64 {
	paddedBytes := make([]byte, 8)
	for i := len(b) - 1; i >= 0; i-- {
		paddedBytes[i] = b[i]
	}
	return binary.LittleEndian.Uint64(paddedBytes)
}

func (d *Decoder) getReg(reg byte, ext bool) Register {
	if !ext {
		switch reg {
		case 0:
			return RAX
		case 1:
			return RCX
		case 2:
			return RDX
		case 3:
			return RBX
		case 4:
			return RSP
		case 5:
			return RBP
		case 6:
			return RSI
		case 7:
			return RDI
		}
	} else {
		switch reg {
		case 0:
			return R8
		case 1:
			return R9
		case 2:
			return R10
		case 3:
			return R11
		case 4:
			return R12
		case 5:
			return R13
		case 6:
			return R14
		case 7:
			return R15
		}
	}
	panic(fmt.Sprintf("unknown register byte=0x%x ext=%t", reg, ext))
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
