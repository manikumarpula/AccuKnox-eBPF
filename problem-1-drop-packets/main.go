package main

import (
        "flag"
        "log"
        "net"
        "os"
        "os/signal"
        "syscall"

        "github.com/cilium/ebpf/link"
)

func main() {
        ifaceName := flag.String("iface", "lo", "Network interface to attach")
        port := flag.Int("port", 4040, "TCP port to drop")
        flag.Parse()

        objs := dropperObjects{}
        if err := loadDropperObjects(&objs, nil); err != nil {
                log.Fatalf("loading objects: %v", err)
        }

        key := uint32(0)
        val := uint32(*port)
        if err := objs.TargetPortMap.Put(key, val); err != nil {
                log.Fatalf("writing target port to map failed: %v", err)
        }
        log.Printf("Configured dropper to block TCP port %d\n", *port)

        iface, err := net.InterfaceByName(*ifaceName)
        if err != nil {
                log.Fatalf("getting interface %q: %v", *ifaceName, err)
        }

        _, err = link.AttachXDP(link.XDPOptions{
                Program:   objs.DropTcpPort,
                Interface: iface.Index,
        })
        if err != nil {
                log.Fatalf("attaching XDP: %v", err)
        }

        log.Printf("XDP program attached to %s. Press Ctrl+C to stop.", *ifaceName)

        stop := make(chan os.Signal, 1)
        signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
        <-stop

}