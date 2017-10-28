# Tools

The Tools repository contains the basic tool set to provide Minary with the basic means to perform the attacks on the target systems.

***Ape***
Ape is the ARP poisoning engine. It is responsible to poison and depoison a target system]s ARP cache table. Ape only works with IPv4 networks. IPv6 spoofing is possible but it is not implemented with this Minary version.

***Sniffer***
Sniffer captures relevant data from the "wire", collecting it and pass the data to the Minary data pipe.

***HttpReverseProxy***
HttpReverseProxy is an HTTP(S) reverse proxy server that redirects incomin requests to the server that is defined within the Host header field.
To extend the servers functionality plugins can be attached during application initialization. Currently the following plugins are available:

  * **SSLStrip**: Strip and Cache/Redirect HTTPS anchor fields and 301/302 redirects
  * **Inject**: When a particular file request is detected instead of processing it send back a prepared file to the client.
  * **Weaken**: Weaken the HTTP security measurements defined in the HTTP request/response header.
  * **HostMapping**: When a client request is aimed to a particular host the host header is replaced by a new header before the proxy server starts processing the actual HTTP(S) request.
