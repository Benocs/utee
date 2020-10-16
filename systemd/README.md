# systemd unit files to make utee reboot safe

These files will allow running / starting / stopping utee as a service with systemd.

# FILES
| file | location | notes |
|------|----------|-------|
| utee-loadbalance         | /etc/default/utee-loadbalance | utee parameters configuration file |
| utee-loadbalance.service | /etc/systemd/system/utee      | systemd service file |


# USAGE

Copy the files to their respective destinations.

Add your utee parameters to `/etc/default/utee-loadbalance`

`sudo systemctl start utee-loadbalance`

`sudo systemctl stop utee-loadbalance`

systemd will automatically restart utee if it crashes.

