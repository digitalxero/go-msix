// Command dumpappxdigests prints the APPX digest table stored inside a signed
// MSIX package's AppxSignature.p7x AND the digests recomputed from the package
// bytes, so the two can be compared for any signer (go-msix, signtool,
// osslsigncode). It is the ground-truth diagnostic for HashMismatch: if a
// signtool-signed package's stored table matches our recomputation, our digest
// semantics agree with Windows AppxSIP; any differing row shows exactly which
// digest diverges.
//
// Recomputation semantics (mirroring osslsigncode appx.c):
//
//	AXPC  SHA-256 of every byte before AppxSignature.p7x's local record
//	AXCD  SHA-256 of the central directory without the signature's entry,
//	      followed by the EOCD rewritten to unsigned counts/size/offset
//	AXCT  SHA-256 of the stored (uncompressed) [Content_Types].xml
//	AXBM  SHA-256 of the stored (uncompressed) AppxBlockMap.xml
//	AXCI  SHA-256 of AppxMetadata/CodeIntegrity.cat when present
//
// ZIP64 archives are not supported (the diagnostic samples are small).
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dumpappxdigests <package.msix>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	fail(err)

	fmt.Printf("package: %s (%d bytes)\n", os.Args[1], len(data))

	stored, err := storedDigestTable(data)
	fail(err)
	fmt.Println("stored digest table (from AppxSignature.p7x):")
	printTable(stored)

	recomputed, err := recomputeDigests(data)
	fail(err)
	fmt.Println("recomputed digest table (from package bytes):")
	printTable(recomputed)

	match := true
	for _, tag := range []string{"AXPC", "AXCD", "AXCT", "AXBM", "AXCI"} {
		s, sok := stored[tag]
		r, rok := recomputed[tag]
		if sok != rok || (sok && !bytes.Equal(s, r)) {
			fmt.Printf("MISMATCH %s stored=%s recomputed=%s\n", tag, optHex(s), optHex(r))
			match = false
		}
	}
	if match {
		fmt.Println("stored and recomputed tables MATCH")
	}
}

// storedDigestTable extracts the APPX digest blob out of the PKCS#7 inside
// AppxSignature.p7x, tolerating both go-msix's and signtool's SIP encodings.
func storedDigestTable(data []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var p7x []byte
	for _, f := range zr.File {
		if f.Name == "AppxSignature.p7x" {
			r, err := f.Open()
			if err != nil {
				return nil, err
			}
			p7x, err = io.ReadAll(r)
			r.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	if p7x == nil {
		return nil, fmt.Errorf("no AppxSignature.p7x in package")
	}
	if len(p7x) < 4 || string(p7x[:4]) != "PKCX" {
		return nil, fmt.Errorf("AppxSignature.p7x lacks PKCX magic")
	}

	type contentInfo struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	var outer contentInfo
	if _, err := asn1.Unmarshal(p7x[4:], &outer); err != nil {
		return nil, fmt.Errorf("outer ContentInfo: %w", err)
	}
	var signed struct {
		Version    int
		Algorithms asn1.RawValue
		Content    contentInfo
	}
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &signed); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	fmt.Printf("eContentType: %s\n", signed.Content.Type.String())

	var indirect struct {
		Data struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		MessageDigest struct {
			Algorithm asn1.RawValue
			Digest    []byte
		}
	}
	if _, err := asn1.Unmarshal(signed.Content.Content.Bytes, &indirect); err != nil {
		return nil, fmt.Errorf("SpcIndirectDataContent: %w", err)
	}
	fmt.Printf("sip attribute OID: %s, sip value: %s\n",
		indirect.Data.Type.String(), hex.EncodeToString(indirect.Data.Value.FullBytes))

	blob := indirect.MessageDigest.Digest
	fmt.Printf("MessageDigest.Digest: %d bytes: %s\n", len(blob), hex.EncodeToString(blob))
	if len(blob) < 4 || string(blob[:4]) != "APPX" {
		return nil, fmt.Errorf("digest blob lacks APPX magic (not a digest table)")
	}
	table := map[string][]byte{}
	for off := 4; off+36 <= len(blob); off += 36 {
		table[string(blob[off:off+4])] = blob[off+4 : off+36]
	}
	return table, nil
}

// recomputeDigests re-derives every APPX digest from the signed package bytes.
// Handles both classic and canonical ZIP64 (makeappx/signtool-form) containers.
func recomputeDigests(data []byte) (map[string][]byte, error) {
	// EOCD: scan backwards for PK\x05\x06.
	eocd := -1
	for i := len(data) - 22; i >= 0; i-- {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 0x05 && data[i+3] == 0x06 {
			eocd = i
			break
		}
	}
	if eocd < 0 {
		return nil, fmt.Errorf("no EOCD")
	}
	var cdOffset, cdSize, z64 int
	zip64 := eocd >= 20 && bytes.Equal(data[eocd-20:eocd-16], []byte{'P', 'K', 0x06, 0x07})
	if zip64 {
		z64 = int(binary.LittleEndian.Uint64(data[eocd-12 : eocd-4]))
		if !bytes.Equal(data[z64:z64+4], []byte{'P', 'K', 0x06, 0x06}) {
			return nil, fmt.Errorf("bad ZIP64 EOCD at %d", z64)
		}
		cdSize = int(binary.LittleEndian.Uint64(data[z64+40 : z64+48]))
		cdOffset = int(binary.LittleEndian.Uint64(data[z64+48 : z64+56]))
	} else {
		cdOffset = int(binary.LittleEndian.Uint32(data[eocd+16 : eocd+20]))
		cdSize = int(binary.LittleEndian.Uint32(data[eocd+12 : eocd+16]))
	}

	// Walk central directory entries; find the signature's entry.
	sigLocal, sigEntryStart, sigEntryLen := -1, -1, 0
	for pos := cdOffset; pos < cdOffset+cdSize; {
		if !bytes.Equal(data[pos:pos+4], []byte{'P', 'K', 0x01, 0x02}) {
			return nil, fmt.Errorf("bad CD entry signature at %d", pos)
		}
		nameLen := int(binary.LittleEndian.Uint16(data[pos+28 : pos+30]))
		extraLen := int(binary.LittleEndian.Uint16(data[pos+30 : pos+32]))
		commentLen := int(binary.LittleEndian.Uint16(data[pos+32 : pos+34]))
		entryLen := 46 + nameLen + extraLen + commentLen
		if string(data[pos+46:pos+46+nameLen]) == "AppxSignature.p7x" {
			sigLocal = int(binary.LittleEndian.Uint32(data[pos+42 : pos+46]))
			sigEntryStart, sigEntryLen = pos, entryLen
		}
		pos += entryLen
	}
	if sigLocal < 0 {
		return nil, fmt.Errorf("no AppxSignature.p7x CD entry")
	}
	table := map[string][]byte{}
	axpc := sha256.Sum256(data[:sigLocal])
	table["AXPC"] = axpc[:]

	// Unsigned central directory: all entries minus the signature's, end
	// records rewritten with unsigned counts, size and offset — in the same
	// form (classic or ZIP64) the file uses.
	var cd bytes.Buffer
	cd.Write(data[cdOffset:sigEntryStart])
	cd.Write(data[sigEntryStart+sigEntryLen : cdOffset+cdSize])
	if zip64 {
		z64rec := append([]byte{}, data[z64:z64+56]...)
		binary.LittleEndian.PutUint64(z64rec[24:32], binary.LittleEndian.Uint64(data[z64+24:z64+32])-1)
		binary.LittleEndian.PutUint64(z64rec[32:40], binary.LittleEndian.Uint64(data[z64+32:z64+40])-1)
		binary.LittleEndian.PutUint64(z64rec[40:48], uint64(cd.Len()))
		binary.LittleEndian.PutUint64(z64rec[48:56], uint64(sigLocal))
		cd.Write(z64rec)
		// The locator points at the ZIP64 EOCD, which follows the unsigned CD.
		loc := append([]byte{}, data[eocd-20:eocd]...)
		binary.LittleEndian.PutUint64(loc[8:16], uint64(sigLocal)+binary.LittleEndian.Uint64(z64rec[40:48]))
		cd.Write(loc)
		cd.Write(data[eocd : eocd+22]) // FF-stub EOCD is unchanged
	} else {
		unsignedEOCD := append([]byte{}, data[eocd:eocd+22]...)
		binary.LittleEndian.PutUint16(unsignedEOCD[8:10], binary.LittleEndian.Uint16(data[eocd+8:eocd+10])-1)
		binary.LittleEndian.PutUint16(unsignedEOCD[10:12], binary.LittleEndian.Uint16(data[eocd+10:eocd+12])-1)
		binary.LittleEndian.PutUint32(unsignedEOCD[12:16], uint32(cd.Len()))
		binary.LittleEndian.PutUint32(unsignedEOCD[16:20], uint32(sigLocal))
		cd.Write(unsignedEOCD)
	}
	cd.Write(data[eocd+22:]) // zip comment, if any
	axcd := sha256.Sum256(cd.Bytes())
	table["AXCD"] = axcd[:]

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for name, tag := range map[string]string{
		"[Content_Types].xml":            "AXCT",
		"AppxBlockMap.xml":               "AXBM",
		"AppxMetadata/CodeIntegrity.cat": "AXCI",
	} {
		for _, f := range zr.File {
			if f.Name != name {
				continue
			}
			r, err := f.Open()
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			_, cErr := io.Copy(h, r)
			r.Close()
			if cErr != nil {
				return nil, cErr
			}
			table[tag] = h.Sum(nil)
		}
	}
	return table, nil
}

func printTable(t map[string][]byte) {
	for _, tag := range []string{"AXPC", "AXCD", "AXCT", "AXBM", "AXCI"} {
		if v, ok := t[tag]; ok {
			fmt.Printf("  %s %s\n", tag, hex.EncodeToString(v))
		}
	}
}

func optHex(b []byte) string {
	if b == nil {
		return "<absent>"
	}
	return hex.EncodeToString(b)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "dumpappxdigests:", err)
		os.Exit(1)
	}
}
