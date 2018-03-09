# ipt_controller

ipt_controller is set of tools that make it easier to control iptables for test uses. At the moment there are 2 tools implemented: `dscper` and `tosser`.

## dscper

`dscper` makes it so the OUTPUT chain in iptables set the DSCP to the value that's passed as argument. Calling `dscper -flush` flushes the OUTPUT chain BE CAREFULL.

## tosser

`tosser` makes it so the OUTPUT chain in iptables set the ToS to the value that's passed as argument. Calling `tosser -flush` flushes the OUTPUT chain BE CAREFULL.
