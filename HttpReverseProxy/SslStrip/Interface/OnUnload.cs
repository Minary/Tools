namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxy.Plugin.SslStrip.Cache;
  using HttpReverseProxyLib;

  public partial class SslStrip
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("SslStrip", Logging.Level.DEBUG, "SslStrip.OnUnload():");

      CacheHsts.Instance.ResetCache();
      CacheRedirect.Instance.RedirectCache.Clear();
    }
  }
}
