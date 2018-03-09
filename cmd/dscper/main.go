package main

import (
	"flag"
	"log"

	"github.com/coreos/go-iptables/iptables"
)

func main() {
	flush := flag.Bool("flush", false, "Flush the output chain")
	dst := flag.String("dst", "", "Destination ip address to set the DSCP for")
	src := flag.String("src", "", "Source ip address to set DSCP for")
	flag.Parse()
	args := flag.Args()

	ipt, _ := iptables.New()

	if *flush {
		flushIptable(ipt)
	} else if flag.NArg() == 1 {
		if *dst != "" {
			setDscpDst(ipt, args[0], *dst)
		} else if *src != "" {
			setDscpSrc(ipt, args[0], *src)
		} else {
			setDscp(ipt, args[0])
		}
	}
}

func setDscp(ipt *(iptables.IPTables), dscp string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-j", "DSCP", "--set-dscp", dscp)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain DSCP is already set to %v", dscp)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-j", "DSCP", "--set-dscp", dscp)
		log.Printf("Set the OUTPUT chain DSCP to %v", dscp)
	}
}

func setDscpDst(ipt *(iptables.IPTables), dscp string, dst string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-d", dst, "-j", "DSCP", "--set-dscp", dscp)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain DSCP is already set to %v", dscp)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-d", dst, "-j", "DSCP", "--set-dscp", dscp)
		log.Printf("Set the OUTPUT chain DSCP to %v", dscp)
	}
}

func setDscpSrc(ipt *(iptables.IPTables), dscp string, src string) {
	present, err := ipt.Exists("mangle", "OUTPUT", "-s", src, "-j", "DSCP", "--set-dscp", dscp)
	if err != nil {
		log.Fatalln(err)
	}
	if present {
		log.Printf("OUTPUT chain DSCP is already set to %v", dscp)
	} else {
		err = ipt.AppendUnique("mangle", "OUTPUT", "-s", src, "-j", "DSCP", "--set-dscp", dscp)
		log.Printf("Set the OUTPUT chain DSCP to %v", dscp)
	}
}

func flushIptable(ipt *(iptables.IPTables)) {
	ipt.ClearChain("mangle", "OUTPUT")
	log.Println("Flushing the output chain")
}
