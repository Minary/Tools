namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class Inject
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("Inject", ProxyProtocol.Undefined, Loglevel.DEBUG, "Inject.OnUnload(): ");
    }
  }
}
