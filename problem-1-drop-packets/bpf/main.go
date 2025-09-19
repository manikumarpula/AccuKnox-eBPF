package main

import (
        "log"
        "net"
        "os"
        "os/signal"
        "syscall"

        "github.com/cilium/ebpf/link"
)

func main() {
        stop := make(chan os.Signal, 1)
        signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

        ifaceName := "lo" // Use the loopback interface for testing
        iface, err := net.InterfaceByName(ifaceName)
        if err != nil {
                log.Fatalf("Getting interface %s failed: %s", ifaceName, err)
        }

        // This uses the generated function from dropper_bpf.go
        objs := dropperObjects{}
        if err := loadDropperObjects(&objs, nil); err != nil {
                log.Fatalf("Loading eBPF objects failed: %s", err)
        }
        defer objs.Close()

        // Attach the XDP program to the network interface
        l, err := link.AttachXDP(link.XDPOptions{
                Program:   objs.DropTcpPort,
                Interface: iface.Index,
        })
        if err != nil {
                log.Fatalf("Attaching XDP program failed: %s", err)
        }
        defer l.Close()

        log.Printf("XDP program attached to %s. Dropping TCP packets on port 4040.", ifaceName)
        log.Println("Press Ctrl+C to stop.")

        // Wait for a stop signal
        <-stop

        log.Println("Program stopped.")
}