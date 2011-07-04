**passdown** analyzes current (or saved) TCP traffic and extracts
transferred files in order to store them to disk. It currently supports
HTTP downloads in IPv4 or IPv6, but can easily extended. Sniffing is done
with scapy_.


.. _scapy: https://www.secdev.org/projects/scapy/


Installation
============

Currently no installation required. Just run `passdown.py`
either as root to search for files in your current traffic or give it a
pcap-file as first argument to work with previous transfers.

passdown depends on scapy, which has to be installed and available.
Try installing it with your preferred method (apt, pacman, yum, ...).
Instead you can just put scapy.py__ in the same directory and be fine.

.. __: https://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz


Hacking
=======

You can hack your own protocol to get files from, by defining a class and
giving it the properties ``name`` and ``regex``. The name should be
human-readable and the regex should match to the traffic returned from the
server (i.e. the party that accepts the TCP connection). The constructor of
your class should accept two parameters: The data streams sent by server
and client (in that order). You can then put the classname in the PROTOCOLS
array. Note that you will have to adjust the filter applied to the ``sniff``
call, unless your protocol runs on tcp port 80 as well ;)

Known Bugs / TODO
=================

* TCP packets are not reordered.
* Retransmissions are not handled
* FIN-Handling is a little wrong
* We sometimes get I/O Errors on our streams
* RST packets are currently unknown to passdown
* No real option/parameter handling, verbosity switches would be nice


