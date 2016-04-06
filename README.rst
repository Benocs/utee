utee - transparent UDP tee proxy
================================

Utee is a tool to transparently (preserve the source IP) replicate a UDP stream
to one or more destinations. It supports to modes of operation: tee and
distribution.

In tee mode, utee duplicates incoming traffic and sends it to the
configured destinations.
In distribution mode, utee distributes the incoming traffic among
the configured destinations. Distribution is done in one of the following
modes:

* round-robin
* hash-based
* hash-based load balancing

Synopsis
--------

utee -l <listenaddr:port> -m <r|d> -n <num_threads> [-H] [-L] <targetaddr:port> [targetaddr:port [...]]

utee -h

Distribution: round-robin
-------------------------

In round-robin mode, the incoming UDP stream is evenly distributed over
all destinations. For example, let there be three destinations: 'a', 'b' and
'c'. Then, the first packet will be sent to 'a', the second to 'b', the third
to 'c'. After that, the fourth packet will again be sent to destination 'a',
the fifth to 'b' and so forth.

Distribution: hash-based
------------------------

In hash-based distribution mode, the destination is selected by calculating a
hash sum over the source IP of the UDP packet. This hash is then modded by the
number of destinations. The resulting number denotes the destination to
replicate the packet to. This has the effect that all packets from one source
will always be sent to the same destination. This mode has the disadvantage
that it might introduce an uneven load on the destinations, depending on the
distribution of the packet rate among the sources.

Distribution: hash-based load balancing
---------------------------------------

This mode is an extension of the hash-based distribution. In addition to
the pure hash-based distribution, it also tries to achieve an even load
for all destinations. For this, utee keeps a mapping which source is being
sent to which destination and counts the number of replicated packets for
each such source-destination pair. After a certain configurable amount of
packets, utee adjusts its mapping in such a way that each destination gets
roughly the same amount of packets. Here, it is assumed that the distribution
of the packet rate over the sources stays more or less constant. This check
whether any remapping is necessary happens regularly.

Examples
--------

duplicate traffic to two destinations using 4 threads:

    utee -l 0.0.0.0:1234 -m d -n 4 192.168.1.2:1234 192.168.1.3:1234

distribute traffic round-robin to two destinations using 4 threads:

    utee -l 0.0.0.0:1234 -m r -n 4 192.168.1.2:1234 192.168.1.3:1234

distribute traffic using hash-based selection of destinations to two
destinations using 4 threads:

    utee -l 0.0.0.0:1234 -m r -n 4 -H 192.168.1.2:1234 192.168.1.3:1234

distribute traffic using hash-based load balancing of destinations to two
destinations using 4 threads:

    utee -l 0.0.0.0:1234 -m r -n 4 -L 192.168.1.2:1234 192.168.1.3:1234
