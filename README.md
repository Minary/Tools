# Tools

The Tools repository contains a basic toolset that provides Minary with the means to perform attacks on target systems.

***APE***
APE (ARP poisoning engine) is the component in the Minary system that conducts the actual attacks.
It consists of the following subparts:
  * **ARP poisoning**: Act as a _man in the middle_ between target systems and the internet gateway 
  * **ARP depoisoning**: Undo the _man in the middle_ and restore the original routing path between client system and internet gateway. 
  * **Routing**: Route received data packets to the actual target system.
  * **DNS poisoning**: Poison client DNS requests. Do that in both directions by either poisoning the actual _DNS request_ or the server's _DNS response_.
  * **Firewalling**: Block data packets or pass them to their actual destination. 
  
From the name you can already guess that APE only works with IPv4 networks (IPv6 doesn't know the ARP concept). IPv6 spoofing is possible but it is not implemented with this Minary version.

***Sniffer***
Sniffer captures relevant data from the "wire", collecting data and passing it to the Minary data pipe where it is evaluated by the activated plugins.

***HttpReverseProxy***
HttpReverseProxy is an HTTP(S) reverse proxy server that redirects incoming requests to the server that is defined within the Host header field.
To extend the server's functionality plugins can be attached during application initialization. Currently the following plugins are available:

  * **InjectCode**: When a particular regex is detected inside the server response data, the text sequence is replaced by a user-defined text/code sequence. The _patched_ server response is then forwarded to the client system.
  * **InjectFile**: When a particular file request is detected, instead of processing it this plugin sends a prepared file to the client system.
  * **HostMapping**: When a client request is aimed at a particular host the host header is replaced by a new header before the proxy server starts processing the actual HTTP(S) request.
  * **RequestRedirect**: When a request to a particular URL is detected, the plugin sends a redirect response that points the client to another location.
  * **SSLStrip**: Strip and Cache/Redirect HTTPS anchor fields and 301/302 redirects
  * **Weaken**: Weaken the HTTP security measurements defined in the HTTP request/response header.
