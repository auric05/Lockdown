#compiler
CC = gcc
#npcap SDK paths and required libraries for packet capture on Windows
LIBS = -IC:/npcap-sdk/Include -LC:/npcap-sdk/Lib/x64 -lwpcap -lws2_32
#default target, builds the capture binary
all: capture
#compile capture.c into capture executable using npcap flags
capture: capture.c
	$(CC) capture.c -o capture $(LIBS)
#remove compiled binary to force a clean rebuild
clean:
	rm -f capture.exe