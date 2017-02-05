namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;

  public partial class ClientRequestSniffer
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("ClientRequestSniffer", ProxyProtocol.Undefined, Loglevel.Debug, "ClientRequestSniffer.ClientRequestSnifferOnUnload(): ");
    }
  }
}
