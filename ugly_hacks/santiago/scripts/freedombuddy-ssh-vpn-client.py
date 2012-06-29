"""The FreedomBuddy SSH VPN Client.

This script automatically sets up an SSH VPN to a specific, trusted host.

#. It pings Santiago's local cache for any SSH VPN hosts run by the
   particular buddy.
#. It attempts to form an SSH VPN on all of those addresses.
#. If all of them fail, it'll ping each of the buddy's Santiagi:

   #. It'll try connecting to all the addresses returned by each
      Santiago before moving on to the next Santiago.

This is generic and doesn't need to live in this script.

When connecting, it must do the following:

https://duckduckgo.com/?q=ssh+vpn
http://bodhizazen.net/Tutorials/VPN-Over-SSH/
http://www.linuxjournal.com/content/ssh-tunneling-poor-techies-vpn
https://help.ubuntu.com/community/SSH_VPN
http://www.faqs.org/docs/Linux-mini/ppp-ssh.html

"""
