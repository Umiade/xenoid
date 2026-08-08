# xenoid-netctl

`xenoid-netctl` applies a profile network address through `NETLINK_ROUTE` and verifies the result through kernel-backed interface queries.

Runtime commands:

```sh
/data/local/tmp/xenoid-netctl status rmnet_data0
/data/local/tmp/xenoid-netctl set-mac rmnet_data0 02:33:44:55:66:77
```

The daemon uses this helper before its shell fallback so rtnetlink, ioctl, and sysfs consumers observe one address.
