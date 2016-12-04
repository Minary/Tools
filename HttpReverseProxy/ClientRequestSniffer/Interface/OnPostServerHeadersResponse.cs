namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Exceptions;


  public partial class ClientRequestSniffer
  {

    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;

      // Send sniffed data to pipe
      this.SendClientRequestDataToPipe(requestObj);

      Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ClientRequestSniffer.ClientRequestSniffer.OnPostServerHeadersResponse(): ");
      return instruction;
    }
  }
}
