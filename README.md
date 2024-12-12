# TOR-RPKI

This is part of the TOR-RPKI project.

## Description

This version of Tor is customized to perform discount and matching selection algorithm described in the [TOR-RPKI repo](https://github.com/z-lu2017/TOR-RPKI.git) For discount selection algorithm, Tor loads in the ROA file and checks relay for ROA coverage. For matching algorithm, Tor loads in ROA and ROV database and checks relay ROA/ROV coverage. For each client, it then checks its ROA/ROV coverage and loads a specific version of the optimized weights for relay selection.


## Acknowledgments

* We modified Tor source code based on Tor version 0.4.8.7. The original Tor code can be found [here](https://git.torproject.org/tor.git)
