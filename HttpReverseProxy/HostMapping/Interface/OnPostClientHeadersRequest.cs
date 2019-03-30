namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;


  public partial class HostMapping
  {

    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (string.IsNullOrEmpty(requestObj.ClientRequestObj.Host))
      {
        return instruction;
      }

      
      string hostName = requestObj.ClientRequestObj.Host.ToLower();

      // If hostname is mapped WITHOUT wildcard
      if (Plugin.HostMapping.Config.MappingsHostname?.Count > 0 &&
          Plugin.HostMapping.Config.MappingsHostname.ContainsKey(hostName) &&
          requestObj.ClientRequestObj.ClientRequestHeaders.ContainsKey("Host"))
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage(
                                                                "HostMapping",
                                                                ProxyProtocol.Undefined,
                                                                Loglevel.Debug,
                                                                "HostMapping.OnPostClientHeadersRequest(): Replacing host \"{0}\" by \"{1}\" (by hostname)",
                                                                requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0].ToString(),
                                                                Plugin.HostMapping.Config.MappingsHostname[hostName]);
        requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Clear();
        requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Add(Plugin.HostMapping.Config.MappingsHostname[hostName]);
        requestObj.ClientRequestObj.Host = Plugin.HostMapping.Config.MappingsHostname[hostName];
      
      // If hostname is mapped WITH wildcard
      }
      else if (Plugin.HostMapping.Config.MappingsHostWildcards?.Count > 0)
      {
        foreach (var replHost in Plugin.HostMapping.Config.MappingsHostWildcards.Keys)
        {
          var mappingPair = Plugin.HostMapping.Config.MappingsHostWildcards[replHost];
          if (mappingPair.PatternReg.Match(hostName).Success)
          {
            this.pluginProperties.PluginHost.LoggingInst.LogMessage(
                                                                    "HostMapping",
                                                                    ProxyProtocol.Undefined,
                                                                    Loglevel.Debug,
                                                                    "HostMapping.OnPostClientHeadersRequest(): Replacing host \"{0}\" by \"{1}\" (by hostname wildcard)",
                                                                    requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0].ToString(),
                                                                    replHost);
            
            requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Clear();
            requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Add(replHost);
            requestObj.ClientRequestObj.Host = replHost;
            break;
          }
        }
      }

      return instruction;
    }
  }
}
