# Dumping a CPU trace to a file

## Setup 

In pcsx-redux, make sure `Debug > Show logs` is enabled.

In the 'Logs' window, hide all logs : `Displayed > Hide all`

To avoid unnecessary noise, you can also skip ISR during CPU traces : `Special > Skip ISR during CPU traces`

![Hide all logs](./images/pcsx_cpu_dump_hide.png)
![Skip ISR during CPU traces](./images/pcsx_cpu_dump_isr.png)

## Begin dump

To dump the CPU traces, launch pcsx-redux with the following command :

```bash
pcsx-redux -stdout -logfile log.txt
# Alternatively, you can use -stdout on its own and pipe the output to a file.
pcsx-redux -stdout >> log.txt
```

You can use [additional flags](./cli_flags.md) to launch an executable/disk image in one go, e.g :

```bash
pcsx-redux -stdout -logfile tst.log -iso image.cue -run
```

## Source 

[https://discord.com/channels/642647820683444236/663664210525290507/882608398993063997](https://discord.com/channels/642647820683444236/663664210525290507/882608398993063997)
