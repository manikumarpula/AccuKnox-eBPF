package main

import (
        "flag"
        "log"
        "os"
        "os/signal"
        "syscall"

        "github.com/cilium/ebpf"
        "github.com/cilium/ebpf/link"
)

const MAX_COMM = 16

func main() {
        // Flags
        port := flag.Uint("port", 4040, "TCP port to allow")
        cgroupPath := flag.String("cgroup", "/sys/fs/cgroup/myfilter", "CGroup path to attach to")
        procName := flag.String("process", "myprocess", "Process name to target")
        flag.Parse()

        if len(*procName) >= MAX_COMM {
                log.Fatalf("Process name '%s' is too long (max %d chars)", *procName, MAX_COMM-1)
        }

        // Handle Ctrl+C
        stopper := make(chan os.Signal, 1)
        signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

        // Load eBPF program
        objs := bpfObjects{}
        if err := loadBpfObjects(&objs, nil); err != nil {
                log.Fatalf("loading objects: %v", err)
        }
        defer objs.Close()

        // Configure maps
        key := uint32(0)

        // Target port
        targetPort := uint16(*port)
        if err := objs.TargetPortMap.Put(key, targetPort); err != nil {
                log.Fatalf("writing target port to map: %v", err)
        }
        log.Printf("Set target port to %d", targetPort)

        // Target process
        comm := make([]byte, MAX_COMM)
        copy(comm, []byte(*procName))
        if err := objs.TargetCommMap.Put(key, comm); err != nil {
                log.Fatalf("writing process name to map: %v", err)
        }
        log.Printf("Set target process to '%s'", *procName)

        // Attach to cgroup
        l, err := link.AttachCgroup(link.CgroupOptions{
                Path:    *cgroupPath,
                Program: objs.BlockPort,
                Attach:  ebpf.AttachCGroupInet4Connect, // New API: replaces CgroupConnect4
        })
        if err != nil {
                log.Fatalf("attaching to cgroup: %v", err)
        }
        defer l.Close()

        log.Printf("eBPF program attached to cgroup %s. Press Ctrl+C to exit.", *cgroupPath)

        // Wait until Ctrl+C
        <-stopper
        log.Println("Received signal, exiting...")
}