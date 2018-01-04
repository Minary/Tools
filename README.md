# Tools

The Tools repository contains the basic tool set to provide Minary with the basic means to perform the attacks on the target systems.

***APE***
APE (ARP poisoning engine) is responsible to poison and depoison a target system's ARP cache table. The name lets already assume that APE only works with IPv4 networks. IPv6 spoofing is possible but it is not implemented with this Minary version.

APE implements **DNS poisoning**. It does that in both directions by either poisoning _DNS requests_ or _DNS responses_.

APE offers firewalling capabilities to either block or pass data packets to their actual destination.



***Sniffer***
Sniffer captures relevant data from the "wire", collecting it and pass the data to the Minary data pipe where the data is evaluated by the activated plugins.

***HttpReverseProxy***
HttpReverseProxy is an HTTP(S) reverse proxy server that redirects incoming requests to the server that is defined within the Host header field.
To extend the servers functionality plugins can be attached during application initialization. Currently the following plugins are available:

  * **InjectCode**: When a particular regex is detected inside the server response data that text sequence is replaced by a selfdefined text/code sequence. The _patched_ server response is then forwarded to the client system.
  * **InjectFile**: When a particular file request is detected instead of processing it this plugin sends a prepared file to the client system.
  * **HostMapping**: When a client request is aimed to a particular host the host header is replaced by a new header before the proxy server starts processing the actual HTTP(S) request.
  * **RequestRedirect**: When a request to a particular URL is detected the plugin sends a redirect response to another location to the client.
  * **SSLStrip**: Strip and Cache/Redirect HTTPS anchor fields and 301/302 redirects
  * **Weaken**: Weaken the HTTP security measurements defined in the HTTP request/response header.
