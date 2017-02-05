namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;


  public partial class ClientRequestSniffer
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "ClientRequestSniffer.OnPostClientHeaderRequest(): ");
      return instruction;
    }
  }
}
