package main

import (
	"flag"
	"log"

	"github.com/coreos/go-iptables/iptables"
)

func main() {
	flush := flag.Bool("flush", false, "Flush the output chain")
	dst := flag.String("dst", "", "Destination ip address to set the tos for")
	src := flag.String("src", "", "Source ip address to set tos for")
	flag.Parse()
	args := flag.Args()

	ipt, _ := iptables.New()

	if *flush {
		flushIptable(ipt)
	} else if flag.NArg() == 1 {
		if *dst != "" {
			settosDst(ipt, args[0], *dst)
		} else if *src != "" {
			settosSrc(ipt, args[0], *src)
		} else {
			settos(ipt, args[0])
		}
	}
}

func settos(ipt *(iptables.IPTables), tos string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-j", "TOS", "--set-tos", tos)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain tos is already set to %v", tos)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-j", "TOS", "--set-tos", tos)
		log.Printf("Set the OUTPUT chain tos to %v", tos)
	}
}

func settosDst(ipt *(iptables.IPTables), tos string, dst string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-d", dst, "-j", "TOS", "--set-tos", tos)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain tos is already set to %v", tos)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-d", dst, "-j", "TOS", "--set-tos", tos)
		log.Printf("Set the OUTPUT chain tos to %v", tos)
	}
}

func settosSrc(ipt *(iptables.IPTables), tos string, src string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-s", src, "-j", "TOS", "--set-tos", tos)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain tos is already set to %v", tos)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-s", src, "-j", "TOS", "--set-tos", tos)
		log.Printf("Set the OUTPUT chain tos to %v", tos)
	}
}

func flushIptable(ipt *(iptables.IPTables)) {
	ipt.ClearChain("mangle", "OUTPUT")
	log.Println("Flushing the output chain")
}
