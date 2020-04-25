package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/arch/x86/x86asm"
)

var (
	showInstructions = true
	runInstructions  = false
)

type OpCodeType int

const (
	ImmToReg OpCodeType = iota
	ImmToRegModRM
	RegToReg
	DataToReg
	RegToData
)

type OpCode int

func (o OpCode) String() string {
	switch o {
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
	Mov OpCode = iota
	Xor
	Add
	Syscall
)

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

type Instruction struct {
	inst          x68asm.Inst
	opCode        OpCode
	regSrc        Register
	regDst        Register
	imm           uint64
	dataIndex     uint64
	indexPosition int
}

func (inst Instruction) String() string {
	s := fmt.Sprintf("0x%x) %s", inst.indexPosition, inst.opCode)
	if inst.regDst != RUnknown && inst.regSrc != RUnknown {
		s += fmt.Sprintf(" %s, %s", inst.regDst, inst.regSrc)
	} else if inst.regDst != RUnknown && inst.regSrc == RUnknown {
		// TODO: This is very hacky since it assumes the dataIndex
		// will never be zero, which is just false. Possibly use
		// the opcode type to format an instruction more
		// concretely.
		if inst.dataIndex > 0 {
			s += fmt.Sprintf(" %s, ds:0x%x", inst.regDst, inst.dataIndex)
		} else {

			s += fmt.Sprintf(" %s, 0x%x", inst.regDst, inst.imm)
		}
	}
	return s
}

type Program struct {
	file               *elf.File
	instructionSection Section
	dataSections       []Section
}

func NewProgram(e *elf.File) *Program {
	return &Program{file: e, dataSections: []Section{}}
}

func (p *Program) addInstructionSection(s Section) {
	// TODO: This should error
	p.instructionSection = s
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
	if showInstructions {
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
		for _, ir := range p.instructionSection.irs {
			fmt.Printf("%v\n", ir)
		}
		fmt.Println()
		fmt.Println()
	}
	if runInstructions {
		state := programState{dataSections: p.dataSections}
		for _, ir := range p.instructionSection.irs {
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
}

type Section struct {
	elfProg      *elf.Prog
	isElfHeader  bool
	instructions []Instruction
	data         []byte
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
			i := int(start)
			instructions := []Instruction{}
			for {
				if i >= len(buf) {
					break
				}
				inst, err := x86asm.Decode(buf[i:], 64)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					return
				}
				i += inst.Len
				instructions = append(instructions, Instruction{
					inst: inst,
				})
			}
			program.addInstructionSection(Section{elfProg: prog, instructions: instructions, isElfHeader: isElfHeader})
		} else if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_R == elf.PF_R) {
			program.addDataSection(Section{elfProg: prog, data: buf, isElfHeader: isElfHeader})
		}
	}
	program.run()
}
