package fips

// int bridge_FIPS_mode(void *f) {
//     int (*FIPS_mode)(void) = (int (*)(void))f;
//     return FIPS_mode();
// }
import "C"

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/coreos/pkg/dlopen"
)

const procSysFipsEnabledPath = "/proc/sys/crypto/fips_enabled"

var libPaths = []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}

// SystemReport reports the value of
// of a system property and possible related errors
type SystemReport struct {
	Value bool
	Err   error
}

// FipsSystemReport describes whether FIPS is
// enabled or compatible for different components
// of the system
type FipsSystemReport struct {
	// FipsMode is true if the host/container
	// is currently running in FIPS mode, false othewise
	FipsMode *SystemReport
	// CryptoLibsFips is true if the host/container
	// OpenSSL crypto libraries are FIPS-capable
	CryptoLibsFips *SystemReport
	// FipsCompatibleGoBinary is true if a given
	// Go binary has been compiled so that its
	// stdlib crypto routines call into a FIPS-compliant
	// crypto shared library
	FipsCompatibleGoBinary *SystemReport
}

func isHostRunningInFips() *SystemReport {
	b, err := os.ReadFile(procSysFipsEnabledPath)
	if err != nil {
		return &SystemReport{
			Err: fmt.Errorf("cannot read %s file %w", procSysFipsEnabledPath, err),
		}
	}
	return &SystemReport{
		Value: b[0] == '1',
		Err:   nil,
	}
}

func findCryptoLibsInDir(dir string) []string {
	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 {
		return []string{}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{}
	}

	libs := []string{}
	validLibName := regexp.MustCompile(`^libcrypto.*\.so($|\..*)`)

	for i := range entries {
		if !entries[i].IsDir() && entries[i].Type().IsRegular() {
			if validLibName.MatchString(entries[i].Name()) {
				libs = append(libs, entries[i].Name())
			}
		}
	}
	return libs
}

func findCryptoLibs() ([]string, error) {
	libCryptoPaths := []string{}

	for i := range libPaths {
		if cryptoLibs := findCryptoLibsInDir(libPaths[i]); len(cryptoLibs) > 0 {
			libCryptoPaths = append(libCryptoPaths, cryptoLibs...)
		}
	}

	if len(libCryptoPaths) == 0 {
		return []string{}, errors.New("The OpenSSL library is not installed")
	}
	return libCryptoPaths, nil
}

func isCryptoLibFips() *SystemReport {
	var libsErr error

	cryptoLibs, err := findCryptoLibs()
	if err != nil {
		libsErr = fmt.Errorf("no crypto libraries have been found %w", err)
	}

	for i := range cryptoLibs {
		lib, err := dlopen.GetHandle([]string{cryptoLibs[i]})
		if err != nil {
			libsErr = fmt.Errorf("cannot dlopen %s crypto library %w", cryptoLibs[i], err)
			continue
		}
		defer lib.Close()

		_, err = lib.GetSymbolPointer("FIPS_mode")
		if err != nil {
			libsErr = fmt.Errorf("%s is not FIPS-capable %w", cryptoLibs[i], err)
			continue
		}
		return &SystemReport{
			Value: true,
			Err:   nil,
		}
	}

	return &SystemReport{
		Value: false,
		Err:   libsErr,
	}
}

func isGoBinaryFipsCapable(bin string) *SystemReport {
	if len(bin) < 1 {
		return &SystemReport{Value: false}
	}
	elfBin, err := elf.Open(bin)
	if err != nil {
		return &SystemReport{Err: fmt.Errorf("%s is not an ELF binary", bin)}
	}
	defer elfBin.Close()

	regex := regexp.MustCompile(".*FIPS_mode.*")
	syms, _ := elfBin.Symbols()
	for i := range syms {
		if regex.MatchString(syms[i].Name) &&
			syms[i].Section >= elf.SHN_UNDEF &&
			syms[i].Section < elf.SHN_LORESERVE {
			return &SystemReport{
				Value: true,
			}
		}
	}
	return &SystemReport{
		Value: false,
	}
}

// FipsSystemCheck checks different components of the system
// and reports whether a given Go binary is running or is
// capable to run in FIPS mode
func FipsSystemCheck(goBinary string) *FipsSystemReport {
	return &FipsSystemReport{
		FipsMode:               isHostRunningInFips(),
		CryptoLibsFips:         isCryptoLibFips(),
		FipsCompatibleGoBinary: isGoBinaryFipsCapable(goBinary),
	}
}
