namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib;

  public partial class ClientRequestSniffer
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("ClientRequestSniffer", Loglevel.DEBUG, "ClientRequestSniffer.ClientRequestSnifferOnUnload(): ");
    }
  }
}
