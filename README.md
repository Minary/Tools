# Tools

The Tools repository contains the basic tool set to provide Minary with the basic means to perform the attacks on the target systems.

***APE***
APE (ARP poisoning engine) is the component in the Minary system that conducts the actual attacks on the target systems.
It consists of the following subparts:
  * **ARP poisoning**: Act as a _Man in the middle_ between target systems and the internet gateway 
  * **ARP depoisoning**: Undo the _Man in the middle_ and restore the original routing path between client system and internet gateway. 
  * **Routing**: Route received data packets to the actual target system.
  * **DNS poisoning**: Poison client DNS requests. Do that in both directions by either poisoning the actual _DNS request_ or the servers _DNS response_.
  * **Firewalling**: Block data packets or pass them to their actual destination. 
  
The name lets already assume that APE only works with IPv4 networks (IPv6 doesn't know the ARP concept). IPv6 spoofing is possible but it is not implemented with this Minary version.

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
