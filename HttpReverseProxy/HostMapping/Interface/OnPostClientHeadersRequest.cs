namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.Linq;


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

      // If hostname is mapped without wildcard
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

      }
      else if (Plugin.HostMapping.Config.MappingsHostWildcards?.Count > 0)
      {
        foreach (var key in Plugin.HostMapping.Config.MappingsHostWildcards.Keys)
        {
          if (hostName.EndsWith(key))
          {
            this.pluginProperties.PluginHost.LoggingInst.LogMessage(
                                                                    "HostMapping",
                                                                    ProxyProtocol.Undefined,
                                                                    Loglevel.Debug,
                                                                    "HostMapping.OnPostClientHeadersRequest(): Replacing host \"{0}\" by \"{1}\" (by hostname wildcard)",
                                                                    requestObj.ClientRequestObj.ClientRequestHeaders["Host"][0].ToString(),
                                                                    Plugin.HostMapping.Config.MappingsHostWildcards[key]);
            requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Clear();
            requestObj.ClientRequestObj.ClientRequestHeaders["Host"].Add(Plugin.HostMapping.Config.MappingsHostWildcards[key]);
            requestObj.ClientRequestObj.Host = Plugin.HostMapping.Config.MappingsHostWildcards[key];
            break;
          }

//Plugin.HostMapping.Config.MappingsHostWildcards.Where(elem => hostName.EndsWith(elem.Key))
        }
      }

      return instruction;
    }
  }
}
