namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class SslStrip
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Debug, "SslStrip.OnUnload():");

      this.cacheHsts.ResetCache();
      this.cacheRedirect.RedirectCache.Clear();
    }
  }
}
