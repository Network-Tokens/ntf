## NTF Bess plugin

Network Token Function (NTF) is a datapath library that implements network token processing, as defined in the [relevant I-D](https://github.com/Network-Tokens/network-tokens-rfc/blob/master/draft-yiakoumis-network-tokens-00.txt).

### Features

* Supported Protocols for token encapsulation
  - STUN Attributes
* Supported token types
  - User-centric tokens (symmetric encryption, expiration time, bound IPs)

### Usage

NTF is implemented as a [BESS plugin](https://github.com/NetSys/bess).
This guide assumes some familiarity with installing and using BESS. Self-contained instructions are WIP.

To try NTF, perform the following steps:

* Install BESS using the Vagrantfile instructions mentioned on BESS repo
* Mount this directory on the BESS VM, under `/opt/ntf/`
* Compile bess with `./build.py --plugin /opt/ntf`
* Start BESS and load the NTF pipeline: `run /opt/ntf/bessctl/conf/ntf`

This will bring-up an NTF module and install a network token entry to the NTF, along with encryption key and action details.
Once loaded, it will send traffic from the sample pcap file under pcap-samples through the NTF. This pcap file contains recorded traffic from a video call (using Jitsi), where network tokens are attached as STUN attributes to video flows.

The NTF will detect the token, and apply defined actions (currently setting a DSCP marking). 
The output of the NTF will be available at `/tmp/uplink.pcap`
