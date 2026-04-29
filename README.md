# warframe-nrs-server

A source-available implementation of a NAT Relay Server for Warframe.

## Usage

To start the server, run `warframe-nrs-server <deployment type>`, where deployment type must be one of the following:
- `lan-pc`: Binds to the first physical network adaptor while keeping ports that the game client might use free. Set `"nrsAddresses"` to `["<lan ip>:1234"]`. The adaptor name and its LAN IP will be printed at startup.
- `lan-server`: Binds to the first physical network adaptor with no reservations about which ports it uses. Set `"nrsAddresses"` to `["<lan ip>"]`. The adaptor name and its LAN IP will be printed at startup.
- `public`: Binds to all interfaces with no reservations about which ports it uses but assumes that clients will reach this server via its public IP, which will also be printed at startup.
