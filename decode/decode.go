package decode

import (
	"encoding/binary"
	"fmt"
	"io"
)

type OpCode struct {
	Code      byte
	RegCode   byte
	Type      OpCodeType
	Inst      Inst
	UsesModRM bool // wtf does this do / mean?
	Size      int
}

func (o OpCode) String() string {
	return o.Inst.String()
}

var opCodes = []OpCode{
	{0xb8, 0, ImmToReg, Mov, false, 0},
	{0x89, 0x03, RegToReg, Mov, true, 0},
	{0x89, 0, RegToData, Mov, true, 0},
	{0x8b, 0, DataToReg, Mov, true, 4},
	{0x83, 0, ImmToRegModRM, Add, true, 1},
	{0x81, 0, ImmToRegModRM, Xor, true, 4},
	{0x83, 0x06, ImmToRegModRM, Xor, true, 1},
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
		// If we don't find a match with regCode, check for any
		// exact matches for actual opcode.
		// TODO: again, unsure if this is correct.
		for _, o := range foundOpCodes {
			if o.Code == b {
				return o, nil
			}
		}
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
		case DataToReg:
			d.handleDataToReg(opCode)
		default:
			return nil, fmt.Errorf("unhandled opcode type: %d (0x%x)", d.Data[d.i], d.Data[d.i])
		}
		fmt.Printf("%v\n", d.irs[len(d.irs)-1])
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

func (d *Decoder) handleDataToReg(o OpCode) {
	regDstByte := d.modrm.Reg
	regDst := d.getReg(regDstByte, d.rex.R)
	// TODO: wtf is this?
	d.i++
	d.irs = append(d.irs, IR{
		opCode:        o,
		regDst:        regDst,
		dataIndex:     d.binaryFromBytes(d.Data[d.i : d.i+o.Size]),
		indexPosition: d.startI,
	})
	// fmt.Printf("IR=%#v\n", d.irs[len(d.irs)-1])
	d.i += o.Size
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
